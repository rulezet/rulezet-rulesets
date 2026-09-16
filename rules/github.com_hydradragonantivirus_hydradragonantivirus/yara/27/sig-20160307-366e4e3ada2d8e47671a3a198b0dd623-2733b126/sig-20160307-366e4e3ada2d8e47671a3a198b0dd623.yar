rule sig_20160307_366e4e3ada2d8e47671a3a198b0dd623 {
  meta:
    description = "datamaliciousorder - file 20160307_366e4e3ada2d8e47671a3a198b0dd623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6df237828b3065a7a7642859c35532dedb70ba586febbd5f4e7fd4f23bb987a"

  strings:
    $s1  = "results[matchesSelector + buildFragment](removeAttribute, match + oMatchesSelector + push_native + inArray + offsetParent + cont" ascii
    $s2  = "ext + focusin + compare + timeStamp + statusCode, !((((((40 * prop + 34)) + (Math.pow((reject ^ 32), (col | 2)) - (version - 267" ascii
    $s3  = "pseudo[setRequestHeader + matchesSelector + rhash + conv] = (1 + -curCSSLeft);" fullword ascii
    $s4  = "eft + 2) & (curCSSLeft * 3)))) | (((curCSSLeft ^ (22 - rscriptType)) + ((3 + col) ^ (1 + -curCSSLeft))) ^ ((23 - test) + (0 ^ co" ascii
    $s5  = "combinator = stopImmediatePropagation[done + checkbox + handlerQueue + needsContext + computeStyleTests + code + keyHooks + mous" ascii
    $s6  = "7))) / (((rneedsContext + 144), (Math.pow(list, 2) - keepScripts), (106, cache, 10)) * ((curCSSLeft + 2) ^ (a - 25)) + ((curCSSL" ascii
    $s7  = "-(curCSSLeft & 1))) ^ (((hasContent & 15)) - (prop | 0) * (clearInterval) * (11 - protocol))))));" fullword ascii
    $s8  = "rejectWith[sourceIndex + options](results[split + button + computeStyleTests + rnoContent]);" fullword ascii
    $s9  = "eenter + jsonProp](isArray + scrollTo + insertBefore) + merge + matchesSelector + hidden + computeStyleTests + eventDoc + rnativ" ascii
    $s10 = "val / 1) * (prop & 2) | ((col & 1) / (clearInterval & 3)))) + ((((DOMParser - 72) * (before & 7) + (box & 15)), ((dirruns, 1) + " ascii
    $s11 = "combinator = stopImmediatePropagation[done + checkbox + handlerQueue + needsContext + computeStyleTests + code + keyHooks + mous" ascii
    $s12 = "focus[rparentsprev + func] = ((4 - clearInterval) & (1 ^ col));" fullword ascii
    $s13 = "while (results[fcamelCase + valHooks + computeStyleTests] < (26 / hasContent) * 2) {" fullword ascii
    $s14 = "l)))) == (2 * ((((attrId + 90) - (reject | 56)) & ((delegate, 18, sortOrder, 93) - (clearInterval, 67, bup))) / (3 * (clearInter" ascii
    $s15 = "rejectWith[padding + bind]();" fullword ascii
    $s16 = "rejectWith[soFar + stopOnFalse + initial](combinator, (1 + curCSSLeft));" fullword ascii
    $s17 = "isLocal[msFullscreenElement + curCSSTop + _queueHooks][removeClass](((noGlobal ^ 118) | (complete / 28)));" fullword ascii
    $s18 = "rejectWith = isLocal[fired + context][opts + unquoted + chainable + origType](success + wrapMap + dataAttr + clazz + pixelPositi" ascii
    $s19 = "results = isLocal[msFullscreenElement + selection][tabIndex + parentNode + ajaxSetup + guaranteedUnique + createCache](count + i" ascii
    $s20 = "results = isLocal[msFullscreenElement + selection][tabIndex + parentNode + ajaxSetup + guaranteedUnique + createCache](count + i" ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}