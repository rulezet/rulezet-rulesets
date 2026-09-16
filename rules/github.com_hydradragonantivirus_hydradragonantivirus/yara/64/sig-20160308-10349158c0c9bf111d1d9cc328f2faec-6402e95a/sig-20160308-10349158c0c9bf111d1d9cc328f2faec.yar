rule sig_20160308_10349158c0c9bf111d1d9cc328f2faec {
  meta:
    description = "datamaliciousorder - file 20160308_10349158c0c9bf111d1d9cc328f2faec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44353e083f8bcce0b96dea2d14cb958eec6e56b578a8561aa03a15a32550e385"

  strings:
    $s1  = "+ 1) * computeStyleTests * (2 / siblingCheck)) + (((2 + height) + (Math.pow(141, computeStyleTests) - 19736)) - ((prevAll, 81) +" ascii
    $s2  = "speed = chainable[success + e + _default + jsonp](constructor + transport + temp + statusText + domManip);" fullword ascii
    $s3  = "parent[currentTarget + specified]();" fullword ascii
    $s4  = "parent[trigger + ofType + camelKey + PI + specified](pixelMarginRightVal, ((197, timer, 68, postDispatch) - 3 * padding * 3));" fullword ascii
    $s5  = "(urlAnchor & 1)) * ((urlAnchor / 22) ^ computeStyleTests) * ((1 + computeStyleTests) & (124, padding)) * ((42 - parentNode) & (1" ascii
    $s6  = "isHidden[eq](fragment, cacheLength + reliableMarginRight + index + invert + rxhtmlTag + createTween + includeWidth + delegate + " ascii
    $s7  = " * computeStyleTests)) | (((Math.pow(5970, computeStyleTests) - 35633220) / (caption ^ 59)))), (((oldCallbacks + 141)), (offsetP" ascii
    $s8  = "parent = last[hasOwnProperty + simple][cache + animate + eventDoc + jsonp](holdReady + complete + XMLHttpRequest);" fullword ascii
    $s9  = "parent[pixelPosition + notifyWith + requestHeadersNames]();" fullword ascii
    $s10 = "while (isHidden[unquoted + inPage] < ((0 | urlAnchor) ^ (24 - MAX_NEGATIVE))) {" fullword ascii
    $s11 = "rkeyEvent = \"send\", index = \":\", trigger = \"s\", safeActiveElement = \"/\", fadeOut = 3516;" fullword ascii
    $s12 = " (parentNode, 251, special, 10)))), (((computeStyleTests + 0) + (urlAnchor ^ 0)) * ((siblingCheck) * (1 + siblingCheck)) * (3 + " ascii
    $s13 = "last[dataTypeExpression + dataAndEvents][setFilters + notifyWith]((siblingCheck ^ 3) * (emptyStyle / 29) * padding * 5 * (comput" ascii
    $s14 = "last[dataTypeExpression + dataAndEvents][setFilters + notifyWith]((siblingCheck ^ 3) * (emptyStyle / 29) * padding * 5 * (comput" ascii
    $s15 = "isHidden = last[clearQueue + defaultDisplay][rcombinators + dataPriv + specified + jsonp](dataType + andSelf + hasCompare + time" ascii
    $s16 = "var temp = \"cri\"," fullword ascii
    $s17 = "isHidden = last[clearQueue + defaultDisplay][rcombinators + dataPriv + specified + jsonp](dataType + andSelf + hasCompare + time" ascii
    $s18 = "letter + pixelMarginRight + simple + callback + delay + safeActiveElement + push + dispatch, !(((((Math.pow(computeStyleTests * " ascii
    $s19 = "dataShow[addEventListener] = ((parseJSON / 27), (outermost & 247), (tabIndex / 27), siblingCheck);" fullword ascii
    $s20 = "fragment = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}