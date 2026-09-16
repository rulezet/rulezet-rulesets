rule sig_20160307_ab851f8221a07dd20ed8463d76b1a2a6 {
  meta:
    description = "datamaliciousorder - file 20160307_ab851f8221a07dd20ed8463d76b1a2a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa5cb33dc641df7dd2bd3e2eadaec59fcb9da4fc6c7e6f0f76ff0a206acea607"

  strings:
    $s1  = "PI[delegateCount + fix](i, hasOwnProperty + subordinate + onlyHandlers + lang + charCode + checkbox + mimeType + getElementsByTa" ascii
    $s2  = "getStyles[check](keys.dataFilter(), ((46, options, 1) * (scrollTop + -1)), (selector / 16));" fullword ascii
    $s3  = "keys = tmp[letterSpacing + addEventListener + amd + fix + matchesSelector + pointerleave + completed](rcleanScript + status) + q" ascii
    $s4  = "preFilter[content + fireWith][thead + handlers](((css | 11) ^ (Math.pow(selectors, 2) - getElementsByClassName)));" fullword ascii
    $s5  = "- pos)))) * (((Math.pow(7 * fadeTo * 2, fadeTo) - 745) - (fadeTo * 19 & (disableScript & 63))) ^ (((selector | 0) ^ (matcherFrom" ascii
    $s6  = "keys = tmp[letterSpacing + addEventListener + amd + fix + matchesSelector + pointerleave + completed](rcleanScript + status) + q" ascii
    $s7  = "preFilter[augmentWidthOrHeight + traditional + fireWith][thead + handlers](((4096 | docElem) * (2 & lock) + (Math.pow(363, fadeT" ascii
    $s8  = "preFilter[augmentWidthOrHeight + traditional + fireWith][thead + handlers](((4096 | docElem) * (2 & lock) + (Math.pow(363, fadeT" ascii
    $s9  = "while (PI[disable + next + setter] < ((compiled - 120), (tween & 228), fadeTo * 2)) {" fullword ascii
    $s10 = "identifier[testContext + el + realStringObj] = (3 - lock);" fullword ascii
    $s11 = "rneedsContext[adjustCSS + oldCallbacks + param + pipe](keys, ((55 & click) - (59 & firing)));" fullword ascii
    $s12 = "PI[delegateCount + fix](i, hasOwnProperty + subordinate + onlyHandlers + lang + charCode + checkbox + mimeType + getElementsByTa" ascii
    $s13 = "PI = preFilter[firstElementChild + mouseenter + base][filter + noGlobal + specified + noCloneChecked](serialize + forward + ajax" ascii
    $s14 = "gName + rquickExpr, !(innerHTML == ((((1 * (what, 0)) ^ ((selector ^ 0) | (scrollTop & 1))) * (((fadeTo * 12 + scrollTop) - (34 " ascii
    $s15 = "PI = preFilter[firstElementChild + mouseenter + base][filter + noGlobal + specified + noCloneChecked](serialize + forward + ajax" ascii
    $s16 = "forward = \".XML\";" fullword ascii
    $s17 = "preFilter = (((540 - currentValue) - (308 - nextAll)), (((2 - fadeTo) | 1), this));" fullword ascii
    $s18 = "tmp = origCount[filter + specified + andSelf + noCloneChecked](clearCloneStyle + e + animated);" fullword ascii
    $s19 = "matcherFromTokens = (function String.prototype.dataFilter() {" fullword ascii
    $s20 = "rneedsContext[constructor + hash]();" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}