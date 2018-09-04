/*!
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

var Cookie = require('cookie')
var createError = require('http-errors')
var sign = require('cookie-signature').sign
var Tokens = require('csrf')

/**
 * Module exports.
 * @public
 */

module.exports = csurf

/**
 * CSRF protection middleware.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's session.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */

function csurf (options) {
  var opts = options || {}

  // 初始化时设置cookie参数
  var cookie = getCookieOptions(opts.cookie)

  // get session options
  var sessionKey = opts.sessionKey || 'session'

  // 设置从req的什么位置获取token值
  var value = opts.value || defaultValue;

  // 生成操作token的实例
  var tokens = new Tokens(opts)

  // 设置不需要进行csrf token校验的方法，默认为'GET', 'HEAD', 'OPTIONS'
  var ignoreMethods = opts.ignoreMethods === undefined
    ? ['GET', 'HEAD', 'OPTIONS']
    : opts.ignoreMethods

  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError('option ignoreMethods must be an array')
  }

  // 生成一个包含需要被忽略方法的映射表
  var ignoreMethod = getIgnoredMethods(ignoreMethods)

  return function csrf (req, res, next) {
    // validate the configuration against request
    if (!verifyConfiguration(req, sessionKey, cookie)) {
      return next(new Error('misconfigured csrf'))
    }

    // 从cookie中获取生成token的secret，默认secret会保存在cookie的"_csrf"中；若初次请求，secret为undifined
    var secret = getSecret(req, sessionKey, cookie)
    var token

    // 生成token的方法，挂载到req
    req.csrfToken = function csrfToken () {
      // 如果请求req的cookie已经有secret，则会一直使用同样的secret
      var sec = !cookie
        ? getSecret(req, sessionKey, cookie)
        : secret

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token
      }

      if (sec === undefined) {
        // 生成secret
        sec = tokens.secretSync()
        setSecret(req, res, sessionKey, sec, cookie)
      }

      // update changed secret
      secret = sec

      // 每次请求都生成新token
      token = tokens.create(secret)

      return token
    }

    // 初次请求secret不存在
    if (!secret) {
      // 生成secret
      secret = tokens.secretSync()
      // 将secret值在res里写入cookie，默认字段为"_csrf"
      setSecret(req, res, sessionKey, secret, cookie)
    }

    // 根据req cookie传过来的secret值和token，判断是否通过校验
    if (!ignoreMethod[req.method] && !tokens.verify(secret, value(req))) {
      // 若没有通过校验，返回code：EBADCSRFTOKEN
      return next(createError(403, 'invalid csrf token', {
        code: 'EBADCSRFTOKEN'
      }))
    }

    next()
  }
}

/**
 * 根据顺序依次获取token值
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue (req) {
  return (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    (req.headers['csrf-token']) ||
    (req.headers['xsrf-token']) ||
    (req.headers['x-csrf-token']) ||
    (req.headers['x-xsrf-token'])
}

/**
 * 获取cookie配置
 *
 * @param {boolean|object} [options]
 * @returns {object}
 * @api private
 */

function getCookieOptions (options) {
  if (options !== true && typeof options !== 'object') {
    return undefined
  }

  var opts = {
    key: '_csrf',
    path: '/'
  }

  if (options && typeof options === 'object') {
    for (var prop in options) {
      var val = options[prop]

      if (val !== undefined) {
        opts[prop] = val
      }
    }
  }

  return opts
}

/**
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */

function getIgnoredMethods (methods) {
  var obj = Object.create(null)

  for (var i = 0; i < methods.length; i++) {
    var method = methods[i].toUpperCase()
    obj[method] = true
  }

  return obj
}

/**
 * 从cookie中获取生成token的secret
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecret (req, sessionKey, cookie) {
  // get the bag & key
  var bag = getSecretBag(req, sessionKey, cookie)
  var key = cookie ? cookie.key : 'csrfSecret'

  if (!bag) {
    /* istanbul ignore next: should never actually run */
    throw new Error('misconfigured csrf')
  }

  // return secret from bag
  return bag[key]
}

/**
 * 获取cookies
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecretBag (req, sessionKey, cookie) {
  if (cookie) {
    // get secret from cookie
    var cookieKey = cookie.signed
      ? 'signedCookies'
      : 'cookies'

    return req[cookieKey]
  } else {
    // get secret from session
    return req[sessionKey]
  }
}

/**
 * Set a cookie on the HTTP response.
 *
 * @param {OutgoingMessage} res
 * @param {string} name
 * @param {string} val
 * @param {Object} [options]
 * @api private
 */

function setCookie (res, name, val, options) {
  var data = Cookie.serialize(name, val, options)

  var prev = res.getHeader('set-cookie') || []
  var header = Array.isArray(prev) ? prev.concat(data)
    : Array.isArray(data) ? [prev].concat(data)
      : [prev, data]

  res.setHeader('set-cookie', header)
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} sessionKey
 * @param {string} val
 * @param {Object} [cookie]
 * @api private
 */

function setSecret (req, res, sessionKey, val, cookie) {
  if (cookie) {
    // set secret on cookie
    var value = val

    if (cookie.signed) {
      var secret = req.secret

      if (!secret) {
        /* istanbul ignore next: should never actually run */
        throw new Error('misconfigured csrf')
      }

      value = 's:' + sign(val, secret)
    }

    setCookie(res, cookie.key, value, cookie)
  } else if (req[sessionKey]) {
    // set secret on session
    req[sessionKey].csrfSecret = val
  } else {
    /* istanbul ignore next: should never actually run */
    throw new Error('misconfigured csrf')
  }
}

/**
 * Verify the configuration against the request.
 * @private
 */

function verifyConfiguration (req, sessionKey, cookie) {
  if (!getSecretBag(req, sessionKey, cookie)) {
    return false
  }

  if (cookie && cookie.signed && !req.secret) {
    return false
  }

  return true
}
