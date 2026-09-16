rule sig_20160309_152d51b30456eee022f5225c88fc7307 {
  meta:
    description = "datamaliciousorder - file 20160309_152d51b30456eee022f5225c88fc7307.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0631b325306f82787728b841c0495f1f660ddc77170d8daaaf7271b9d5873c5c"

  strings:
    $s1  = "createFxNow[setGlobalEval](r20, superMatcher + getJSON + value + cors + bp + remove + handle + matchContext + unique + col + dup" ascii
    $s2  = "adjustCSS[wrapInner + isSuccess + temp + attrs](stopPropagation, ((tweeners - 32) & (realStringObj * 3)));" fullword ascii
    $s3  = "fix = serialize[hooks + fireGlobals + globalEventContext + unique](getWidthOrHeight + computeStyleTests + one + unique + rbracke" ascii
    $s4  = "adown = createFxNow[script + trim + compiled];" fullword ascii
    $s5  = "prop[forward](stopPropagation.prevUntil(), ((realStringObj + 0) + -realStringObj), ((0 | realStringObj) + -(1 + createTextNode))" ascii
    $s6  = "prop[forward](stopPropagation.prevUntil(), ((realStringObj + 0) + -realStringObj), ((0 | realStringObj) + -(1 + createTextNode))" ascii
    $s7  = "fix = serialize[hooks + fireGlobals + globalEventContext + unique](getWidthOrHeight + computeStyleTests + one + unique + rbracke" ascii
    $s8  = "gObj * 29))) + (((show + 32) - opts) - ((Math.pow(47, isPlainObject) - 2128), (oldCache - 231), (doAnimation * 2 + contents), (1" ascii
    $s9  = "forward = tmp + propName + pdataOld;" fullword ascii
    $s10 = "clientTop[onabort + elemData] = (3 * isPlainObject * 5, (Math.pow(stop, 2) - matchAnyContext), (328 - dir), (0 ^ realStringObj))" ascii
    $s11 = "clientTop[onabort + elemData] = (3 * isPlainObject * 5, (Math.pow(stop, 2) - matchAnyContext), (328 - dir), (0 ^ realStringObj))" ascii
    $s12 = "serialize = originalProperties[empty + rheaders + newDefer + unique];" fullword ascii
    $s13 = "createFxNow[setGlobalEval](r20, superMatcher + getJSON + value + cors + bp + remove + handle + matchContext + unique + col + dup" ascii
    $s14 = "adjustCSS = originalProperties[getWidthOrHeight + charCode + unique][module + cleanData + getAttribute + delegateCount + unique]" ascii
    $s15 = "adjustCSS = originalProperties[getWidthOrHeight + charCode + unique][module + cleanData + getAttribute + delegateCount + unique]" ascii
    $s16 = "(specified + getter + rheaders + serializeArray + fxNow);" fullword ascii
    $s17 = "licates + transport + offset + animate + headers + classCache + nonce, !((((((isPlainObject * 8 + realStringObj) / 17) + (realSt" ascii
    $s18 = "stopPropagation = fix[offsetHeight + finish + pdataOld + select + isLocal + includeWidth + preFilter + pixelPosition](rheader + " ascii
    $s19 = "stopPropagation = fix[offsetHeight + finish + pdataOld + select + isLocal + includeWidth + preFilter + pixelPosition](rheader + " ascii
    $s20 = "originalProperties = (((Math.pow(9, isPlainObject) - 71), (caption / 43), show * 17), (((removeAttr / 27) * (base & 3)), this));" ascii

  condition:
    uint16(0) == 0x7564 and
    8 of them
}