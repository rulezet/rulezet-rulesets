rule sig_20160308_395f13a18690f47956d132a5ea11acf8 {
  meta:
    description = "datamaliciousorder - file 20160308_395f13a18690f47956d132a5ea11acf8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8495a112688e9376b5dff55eb86ff23d323ddcaffc92a569ba07ec78c1c73f78"

  strings:
    $s1  = "getAllResponseHeaders = ((Math.pow((78 - temp), (0 | hasOwn)) - (6510 - nodes)), (((102 / isEmptyObject) ^ (1 + dataPriv)), this" ascii
    $s2  = "getAllResponseHeaders = ((Math.pow((78 - temp), (0 | hasOwn)) - (6510 - nodes)), (((102 / isEmptyObject) ^ (1 + dataPriv)), this" ascii
    $s3  = "getAllResponseHeaders[dataTypeExpression + pos][hasData]((Math.pow((Math.pow(destElements, 2) - beforeSend), (50 - l)) - 2 * has" ascii
    $s4  = "getAllResponseHeaders[delegateCount + left][matcherFromGroupMatchers + tokens + fixHook](((nodeNameSelector * 8 + addGetHookIf) " ascii
    $s5  = " (clientTop + 0))) * (((clientTop * 6) - (keys ^ 0)) ^ (Math.pow(xhrSuccessStatus, (0 | hasOwn)) - (342 / reverse)))) | ((((3, o" ascii
    $s6  = "wrapInner[safeActiveElement + strAbort](isWindow + udataCur + converters, rjsonp + realStringObj + what + push_native + _removeD" ascii
    $s7  = "wrapInner = getAllResponseHeaders[getter + merge + truncate][pop + overflow + css](inspect + stateVal + unit + valHooks + stateV" ascii
    $s8  = "progress = calculatePosition[elementMatchers + version + bulk + originAnchor](once + rdisplayswap + trim + hidden + disableScrip" ascii
    $s9  = "getAllResponseHeaders[delegateCount + left][matcherFromGroupMatchers + tokens + fixHook](((nodeNameSelector * 8 + addGetHookIf) " ascii
    $s10 = "rejectWith = progress[udataCur + isFunction + newDefer + startLength + offsetHeight + tokens + fnOut + rtypenamespace](checkNonE" ascii
    $s11 = "hasData = \"Sleep\", nodeNameSelector = 20006, disableScript = \"l\", _data = \"Time\", tokens = \"e\", trim = \"ip\";" fullword ascii
    $s12 = "al + forward);" fullword ascii
    $s13 = "pow((reverse * 2 + clientTop), (2 | hasOwn)) - (545 + animated))))) == 7));" fullword ascii
    $s14 = "forward = \"HTTP\"," fullword ascii
    $s15 = "bySet = getAllResponseHeaders[nativeStatusText + truncate][elems + time + rbracket](subordinate + padding + mimeType);" fullword ascii
    $s16 = "wrapInner = getAllResponseHeaders[getter + merge + truncate][pop + overflow + css](inspect + stateVal + unit + valHooks + stateV" ascii
    $s17 = "progress = calculatePosition[elementMatchers + version + bulk + originAnchor](once + rdisplayswap + trim + hidden + disableScrip" ascii
    $s18 = "rejectWith = progress[udataCur + isFunction + newDefer + startLength + offsetHeight + tokens + fnOut + rtypenamespace](checkNonE" ascii
    $s19 = "lements + keepData + what) + orig + overwritten + _data + setup + computeStyleTests + nodeValue;" fullword ascii
    $s20 = "while (wrapInner[origFn + innerText + tokens] < ((origName / 33) / hasOwn * 2 * xhrSuccessStatus * 2)) {" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}