rule sig_20160307_576e84a5900a95d1ee7113e8d0b9e9ac {
  meta:
    description = "datamaliciousorder - file 20160307_576e84a5900a95d1ee7113e8d0b9e9ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27d940d132c22120b9488ec2337c70381d50b468fa4f6faa5a1a11cbf54050dc"

  strings:
    $s1  = "startTime = risSimple[clientTop + parse + rcomma + first + preventDefault + run + getScript + wrapInner + until + rchecked + sto" ascii
    $s2  = "checkbox[delegateCount](clone + getBoundingClientRect, vendorPropName + booleans + curCSSLeft + genFx + elementMatchers + origTy" ascii
    $s3  = "startTime = risSimple[clientTop + parse + rcomma + first + preventDefault + run + getScript + wrapInner + until + rchecked + sto" ascii
    $s4  = "transport[curPosition] = ((insertBefore * 2 + getClientRects) - (59 & cssPrefixes));" fullword ascii
    $s5  = "pe + nextSibling + includeWidth + rnative + col, !(((Math.pow((((addCombinator ^ 0) + (animated * 1)) ^ (Math.pow(postMap * 2, (" ascii
    $s6  = "newSelector[type + fadeToggle][complete + toArray]((Math.pow((animated ^ 79), (animated + 1)) - (parts ^ 4949)));" fullword ascii
    $s7  = "while (checkbox[isBorderBox + rcomma + rscriptTypeMasked + nidselect + doScroll] < ((boolHook ^ 0) ^ (load, 4))) {" fullword ascii
    $s8  = "ated))) - ((3 * postMap * 3 + (rbuggyQSA * 5)) | ((detach & 7) & (origName, 5)))) - (((boolHook ^ 0) ^ (animated * 2)) | (Math.p" ascii
    $s9  = "r)))) | (Math.pow((((232, onreadystatechange, 182, camelCase) - (23 ^ tabIndex)) * ((149 - newUnmatched), (14 ^ unit), (26 - cle" ascii
    $s10 = "ow(postMap, 2) - detach))) == (((((104, animated) * (210, prefilterOrFactory, 12, boolHook)) | ((737 - groups) / (777 / href))) " ascii
    $s11 = "identifier[offsetHeight + matchContext + isDefaultPrevented](startTime, (2 & postMap));" fullword ascii
    $s12 = "identifier = newSelector[callbackInverse + complete + needsContext + getAttribute + inPage][v + createHTMLDocument + reliableMar" ascii
    $s13 = "pQueue + optall](copyIsArray + processData + rdashAlpha) + owner + original + callbackExpect + until;" fullword ascii
    $s14 = ") - (3 ^ ((addCombinator & 3) * (apply / 44) + (clientX, 154, qualifier, 1)))))));" fullword ascii
    $s15 = "identifier = newSelector[callbackInverse + complete + needsContext + getAttribute + inPage][v + createHTMLDocument + reliableMar" ascii
    $s16 = "- (((Math.pow(17, addCombinator) - 261) - (interval | 27)) ^ (Math.pow((rCRLF ^ 3), (addCombinator & 3)) - (webkitMatchesSelecto" ascii
    $s17 = "newSelector = (((74 | className) - (65 | boolHook)), (((Math.pow(216, addCombinator) - 46336) / (xhr / 16)), this));" fullword ascii
    $s18 = "checkbox[delegateCount](clone + getBoundingClientRect, vendorPropName + booleans + curCSSLeft + genFx + elementMatchers + origTy" ascii
    $s19 = "identifier[rcssNum + tween]();" fullword ascii
    $s20 = "risSimple = pdataCur[attrHandle + inPage + readyList + rquickExpr + inPage](image + specialEasing + progress);" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    8 of them
}