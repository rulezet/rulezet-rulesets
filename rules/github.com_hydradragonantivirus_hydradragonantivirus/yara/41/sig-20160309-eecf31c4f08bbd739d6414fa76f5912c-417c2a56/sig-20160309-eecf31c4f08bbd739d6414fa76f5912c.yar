rule sig_20160309_eecf31c4f08bbd739d6414fa76f5912c {
  meta:
    description = "datamaliciousorder - file 20160309_eecf31c4f08bbd739d6414fa76f5912c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "948a21de75fc40f245e497b1613af47ee8daa3f9012e7adf0c1881c42a6ab1b7"

  strings:
    $s1  = "responseContainer[clearQueue](newContext + andSelf, matcherFromGroupMatchers + callbackContext + rtypenamespace + pageXOffset + " ascii
    $s2  = "extend[rparentsprev] = ((91 - manipulationTarget) / (20 + unqueued));" fullword ascii
    $s3  = "getAttribute[isWindow + readyState + td](targets, ((2 | reject) & (0 ^ resolveContexts)));" fullword ascii
    $s4  = "getAttribute = fix[_queueHooks + Callbacks + temp + writable][MAX_NEGATIVE + multipleContexts + fadeToggle](fail + valHooks + xh" ascii
    $s5  = "getAttribute = fix[_queueHooks + Callbacks + temp + writable][MAX_NEGATIVE + multipleContexts + fadeToggle](fail + valHooks + xh" ascii
    $s6  = "08 - compile))), (((4 + timer) / (Math.pow(12, match) - 125)) & ((args - 35) & (offsetHeight / 48))))) > parentWindow));" fullword ascii
    $s7  = "targets = opts[hasFocus + rnumnonpx + parent + push_native + domManip + originAnchor + pixelPositionVal + click](createElement +" ascii
    $s8  = "targets = opts[hasFocus + rnumnonpx + parent + push_native + domManip + originAnchor + pixelPositionVal + click](createElement +" ascii
    $s9  = "- 2) * resolveContexts * 2 + (match * 2 + parentWindow)) + ((12 + errorCallback) | (0 | rinputs))), (((221 & relatedTarget) & (4" ascii
    $s10 = "var createElement = \"%TEMP%\";" fullword ascii
    $s11 = "ed + handlerQueue + context + testContext + Sizzle, !(((((Math.pow(errorCallback, 2) - rquery) + (2 ^ (id - 34)))) & ((((rquery " ascii
    $s12 = "opts = completed[MAX_NEGATIVE + combinator + checkOn + rhash + rbracket + Sizzle](_queueHooks + rattributeQuotes + isSuccess + c" ascii
    $s13 = "opts = completed[MAX_NEGATIVE + combinator + checkOn + rhash + rbracket + Sizzle](_queueHooks + rattributeQuotes + isSuccess + c" ascii
    $s14 = "hash = responseContainer[dirruns + compilerCache + j + attrNames];" fullword ascii
    $s15 = "getAttribute[animated](hash);" fullword ascii
    $s16 = "var temp = \"cri\"," fullword ascii
    $s17 = "fix = ((9 | isFunction) * (7 & tokenize) * (2 ^ reject), ((3 * match * (2 & resolveContexts) + 3), this));" fullword ascii
    $s18 = "extend = getAttribute;" fullword ascii
    $s19 = "responseContainer = fix[unshift + focusin + fxNow][opener + lastModified + qualifier](selector + classes + webkitMatchesSelector" ascii
    $s20 = "fix[unshift + status + Sizzle][flag + hasClass]((4 + parentWindow) * (1 * match) * (3 ^ reject) * (23 - unqueued) * (0 | isFunct" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}