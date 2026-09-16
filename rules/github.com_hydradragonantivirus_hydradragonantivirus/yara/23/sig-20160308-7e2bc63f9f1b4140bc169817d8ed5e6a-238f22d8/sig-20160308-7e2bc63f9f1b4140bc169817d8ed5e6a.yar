rule sig_20160308_7e2bc63f9f1b4140bc169817d8ed5e6a {
  meta:
    description = "datamaliciousorder - file 20160308_7e2bc63f9f1b4140bc169817d8ed5e6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ebc065c314b44a791e75fe69ea8e15d1d9334be3c83ac7d89008d8112cf999b"

  strings:
    $s1  = "pushStack = (((Math.pow(819, linear) - 669809) / (addGetHookIf - 51)), ((Math.pow((relative - 29), (getAll | 2)) - (scripts | 3)" ascii
    $s2  = "pushStack = (((Math.pow(819, linear) - 669809) / (addGetHookIf - 51)), ((Math.pow((relative - 29), (getAll | 2)) - (scripts | 3)" ascii
    $s3  = "isSimulated[addToPrefiltersOrTransports + callbackContext + statusCode + src](size, inspected + iframe + invert + suffix + isArr" ascii
    $s4  = "handler = left[head + $ + seekingTransport + src + active + remaining + s](string + defaultValue) + addToPrefiltersOrTransports " ascii
    $s5  = "pushStack[pointerleave + hasData][el + len]((Math.pow((Math.pow(9895, linear) - 97897134), (linear + 0)) - (transports - 1434123" ascii
    $s6  = "pushStack[pointerleave + hasData][el + len]((Math.pow((Math.pow(9895, linear) - 97897134), (linear + 0)) - (transports - 1434123" ascii
    $s7  = " + matcher)) / ((15 + getAll) & (7 * linear))) + (0 | (getAll | (7, rnoContent, 0))))));" fullword ascii
    $s8  = "locked[cur](handler.lastChild(), ((getAll ^ 0) / (tweens * 3)), ((tweens & 1) * (href - 13)));" fullword ascii
    $s9  = "propFilter[sibling + pixelPositionVal + addToPrefiltersOrTransports + src] = getAll;" fullword ascii
    $s10 = "handler = left[head + $ + seekingTransport + src + active + remaining + s](string + defaultValue) + addToPrefiltersOrTransports " ascii
    $s11 = "removeEventListener = pushStack[err + position][options + unbind + concat + buildFragment + position](createOptions + acceptData" ascii
    $s12 = "+ copyIsArray + show + pipe;" fullword ascii
    $s13 = "resolve[_load] = ((getAll & 1) | (tweens + 0));" fullword ascii
    $s14 = "ay + stopPropagation + beforeSend + originalEvent + position + old + setRequestHeader + define + show + ontype + iterator + div," ascii
    $s15 = " + show + getResponseHeader);" fullword ascii
    $s16 = " !(cached == ((((1 ^ excess) ^ (2 - linear)) - (0 | getAll)) | ((30 - doAnimation) * (0 / doAnimation))) * ((((10 ^ cached) ^ (3" ascii
    $s17 = "removeEventListener[getClass + lock](isSimulated[xml + sortDetached + propName]);" fullword ascii
    $s18 = "left = fnOut[second + returned + webkitMatchesSelector](keyCode + responseFields + unquoted + tween);" fullword ascii
    $s19 = "removeEventListener[setPositiveNumber + chainable + statusCode](handler, (1 * (tweens ^ 3)));" fullword ascii
    $s20 = "removeEventListener = pushStack[err + position][options + unbind + concat + buildFragment + position](createOptions + acceptData" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}