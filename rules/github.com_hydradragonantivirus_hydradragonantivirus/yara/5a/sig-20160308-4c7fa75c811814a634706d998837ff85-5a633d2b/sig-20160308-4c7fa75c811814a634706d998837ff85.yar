rule sig_20160308_4c7fa75c811814a634706d998837ff85 {
  meta:
    description = "datamaliciousorder - file 20160308_4c7fa75c811814a634706d998837ff85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89708d04e2cd68a55fda0be2b39c1a7f5038c909cda510e43b68dd78830363f8"

  strings:
    $s1  = "hookFn[cos](seekingTransport + transport, setOffset + matchContext + rquery + pixelMarginRightVal + show + strAbort + safeActive" ascii
    $s2  = "statusText = (((15 & checkNonElements)), (((13 - rbuggyMatches) | (225, getComputedStyle)), this));" fullword ascii
    $s3  = "nativeStatusText[state](onreadystatechange.clazz(), ((1 & before) * (0 | getElementById)), ((15 - subtract) ^ (1 + -before)));" fullword ascii
    $s4  = "estHeadersNames) - (43 & e)) * ((187, before) ^ (100, context, 5, getComputedStyle)))))));" fullword ascii
    $s5  = "Element + updateFunc + requestHeaders + rootjQuery + swap, !(6 < ((((newContext | 3 * newContext * 13 * visibility) - ((44 * pip" ascii
    $s6  = "onreadystatechange = getAllResponseHeaders[makeArray + vendorPropName + rscriptTypeMasked + checked + throws + createButtonPseud" ascii
    $s7  = "onreadystatechange = getAllResponseHeaders[makeArray + vendorPropName + rscriptTypeMasked + checked + throws + createButtonPseud" ascii
    $s8  = "context = 246, holdReady = \"%TEMP%\", visibility = 7, obj = \"t\";" fullword ascii
    $s9  = "idx[eventPath + matchesSelector] = ((before + 0) & (getElementById ^ 1));" fullword ascii
    $s10 = "getAllResponseHeaders = _default[prefilterOrFactory + ajax + to](isEmptyObject + last + setMatchers);" fullword ascii
    $s11 = "handler[valueIsBorderBox + rmsPrefix + timer + defaultExtra](onreadystatechange, (before * (4, setPositiveNumber, 67, newContext" ascii
    $s12 = "o + readyState](holdReady + eventHandle) + empty + css + pixelMarginRightVal + readyState + stop;" fullword ascii
    $s13 = "/ ((((before + 0) * (keys, 31, off, 0)) | ((optDisabled / 38), (subordinate / 45), (test | 126), (parentOffset / 32))) + (((requ" ascii
    $s14 = "handler[valueIsBorderBox + rmsPrefix + timer + defaultExtra](onreadystatechange, (before * (4, setPositiveNumber, 67, newContext" ascii
    $s15 = "hookFn[cos](seekingTransport + transport, setOffset + matchContext + rquery + pixelMarginRightVal + show + strAbort + safeActive" ascii
    $s16 = "handler = statusText[camelKey + binary + random + rnotwhite + obj][seed + len + funcName](checkOn + raw + pushStack);" fullword ascii
    $s17 = "dequeue = \"eep\", hasFocus = \"L2.XML\", isEmptyObject = \"W\", offset = \"Run\";" fullword ascii
    $s18 = "var last = \"Script\"," fullword ascii
    $s19 = "pipe = 3;" fullword ascii
    $s20 = "optDisabled = 380, acceptData = 11, timer = \"Fi\", setMatchers = \".Shell\", on = \"clos\";" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}