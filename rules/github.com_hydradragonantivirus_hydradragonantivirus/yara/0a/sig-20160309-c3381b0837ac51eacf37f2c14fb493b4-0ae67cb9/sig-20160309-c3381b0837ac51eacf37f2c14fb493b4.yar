rule sig_20160309_c3381b0837ac51eacf37f2c14fb493b4 {
  meta:
    description = "datamaliciousorder - file 20160309_c3381b0837ac51eacf37f2c14fb493b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6c5965bcb308b21a0e5d98192fca4844126d47b00873845f82f0171a1ff3456"

  strings:
    $s1  = "callbackInverse[adjustCSS](keepScripts, dataAttr + els + isDefaultPrevented + scale + isPropagationStopped + sortStable + tuple " ascii
    $s2  = "urlAnchor = ((19 * ajaxHandleResponses * 2 + (Math.pow(addEventListener, 2) - eventHandle)), (((Math.pow(8, complete) - 55) | (l" ascii
    $s3  = "urlAnchor = ((19 * ajaxHandleResponses * 2 + (Math.pow(addEventListener, 2) - eventHandle)), (((Math.pow(8, complete) - 55) | (l" ascii
    $s4  = ") / (href)) / ((Math.pow(4, complete) - 10) + (statusCode | 4))) * ((linear ^ 1) * ((subordinate - 31) + _$)) * ((3 & (clientY /" ascii
    $s5  = "groups[testContext](tick.el(), (1 + -_$), ((5 - ajaxHandleResponses) / (Math.pow(24, complete) - 533)));" fullword ascii
    $s6  = "mouseenter = urlAnchor[evt + global + relatedTarget][slideDown + blur + ignored + add + parentsUntil](createOptions + rhtml + se" ascii
    $s7  = "mouseenter = urlAnchor[evt + global + relatedTarget][slideDown + blur + ignored + add + parentsUntil](createOptions + rhtml + se" ascii
    $s8  = "prevAll[active + rootjQuery] = ((beforeunload / 49) & (open - 13));" fullword ascii
    $s9  = " 15)) & ((href + 0) / (linear | 3))) / (((complete * 31 * ajaxHandleResponses * 2 * complete / (0 | parts)) - ((38, rcombinators" ascii
    $s10 = "tick = _default[namespaces + parentOffset + JSON + cssShow + time + isWindow](restoreScript + locked) + styles + finalValue + fr" ascii
    $s11 = "tick = _default[namespaces + parentOffset + JSON + cssShow + time + isWindow](restoreScript + locked) + styles + finalValue + fr" ascii
    $s12 = "parentOffset = \"pandEn\", relatedTarget = \"cript\", checked = \"pos\";" fullword ascii
    $s13 = "urlAnchor[body + reliableMarginLeftVal + clearTimeout][_queueHooks](((errorCallback & 6827) | (matchIndexes * 11 + responseHeade" ascii
    $s14 = "urlAnchor[body + reliableMarginLeftVal + clearTimeout][_queueHooks](((errorCallback & 6827) | (matchIndexes * 11 + responseHeade" ascii
    $s15 = "completeDeferred[checked + htmlPrefilter] = ((linear & 1) / (pixelMarginRight + 0));" fullword ascii
    $s16 = ", 55, complete) ^ (6 | parentNode))), (((40 ^ class2type) * (170, querySelectorAll, 36, complete) + 3 * fns * 3) - complete * (1" ascii
    $s17 = "wrap = \"P\", high = \"dy\", preFilter = \"sav\", closest = \".scr\";" fullword ascii
    $s18 = "mouseenter[addCombinator + register + blur](cos);" fullword ascii
    $s19 = "callbackInverse[adjustCSS](keepScripts, dataAttr + els + isDefaultPrevented + scale + isPropagationStopped + sortStable + tuple " ascii
    $s20 = "mouseenter[preFilter + getWidthOrHeight + blur](tick, ((linear | 74) / (callbackExpect & 61)));" fullword ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}