rule sig_20160308_5eb81b0809ff3910f0eb9fd61a758c9b {
  meta:
    description = "datamaliciousorder - file 20160308_5eb81b0809ff3910f0eb9fd61a758c9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fc3cbc51e532a030a4646d2b5be97261b2085f38918669152ad893e8b1abc8c"

  strings:
    $s1  = "accepts[random](tmp, keyCode + apply + rhash + elementMatchers + onerror + destElements + identifier + htmlPrefilter, !((((((21 " ascii
    $s2  = "* matchesSelector + 12) / (async & 60)) + ((firstElementChild * 3 + fail) | (Math.pow(6, e) - 27))) + ((disableScript * 7 * disa" ascii
    $s3  = "hooks = hasContent[keyHooks + list + tabIndex + expand + fadeTo + pixelMarginRightVal + speed + rhash](view + handler + preventD" ascii
    $s4  = "hooks = hasContent[keyHooks + list + tabIndex + expand + fadeTo + pixelMarginRightVal + speed + rhash](view + handler + preventD" ascii
    $s5  = "bleScript * 3 & (src + 185)) - (Math.pow((push_native & 94), (handle, 176, toSelector, 2)) - (types & 12088)))), ((((eventDoc * " ascii
    $s6  = "accepts[random](tmp, keyCode + apply + rhash + elementMatchers + onerror + destElements + identifier + htmlPrefilter, !((((((21 " ascii
    $s7  = "accepts = ridentifier[triggered + name][rnoContent + preMap + origCount](binary + cleanData + sourceIndex);" fullword ascii
    $s8  = "ridentifier = (((32 | styles) ^ (103 - push)), ((23 - (holdReady * 2 + _jQuery)), this));" fullword ascii
    $s9  = "ipt * 29 * e * 2) - (Math.pow((handlerQueue, 120, isXML), (0 ^ e)) - (Math.pow(1194, e) - 1424316))))) == ((((letter & 1) ^ (max" ascii
    $s10 = "dataAttr[dataTypeExpression + elementMatchers + hasCompare] = ((hasFocus ^ 26) - (prefix - 41));" fullword ascii
    $s11 = "duration[completeDeferred] = ((newUnmatched / 25) - (e ^ 4));" fullword ascii
    $s12 = "udataCur[originalSettings](hooks.events(), ((assert, 10) - (holdReady ^ 3)), ((maxWidth + -1) | (letter / 30)));" fullword ascii
    $s13 = "ridentifier[parsed + ajaxHandleResponses][fcamelCase]((Math.pow((102 - cssProps), 2) - (inspect / 47)));" fullword ascii
    $s14 = "unmatched = ridentifier[lastChild + style + reliableMarginLeft + ajaxHandleResponses][height + flag + Deferred](rnative + offset" ascii
    $s15 = "hasContent = isArrayLike[deepDataAndEvents + gotoEnd + msFullscreenElement + elementMatchers](triggered + letterSpacing + colgro" ascii
    $s16 = "hasContent = isArrayLike[deepDataAndEvents + gotoEnd + msFullscreenElement + elementMatchers](triggered + letterSpacing + colgro" ascii
    $s17 = "2 + removeClass) / (14 + until)) - ((15 ^ teardown) & (1036 / isXML))) * ((Math.pow((14 * e + 10), (e ^ 0)) - e * 2 * disableScr" ascii
    $s18 = "Width + checked + readyList);" fullword ascii
    $s19 = "unmatched[isArray + tweener](accepts[matchers + createElement + bind]);" fullword ascii
    $s20 = "unmatched = ridentifier[lastChild + style + reliableMarginLeft + ajaxHandleResponses][height + flag + Deferred](rnative + offset" ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}