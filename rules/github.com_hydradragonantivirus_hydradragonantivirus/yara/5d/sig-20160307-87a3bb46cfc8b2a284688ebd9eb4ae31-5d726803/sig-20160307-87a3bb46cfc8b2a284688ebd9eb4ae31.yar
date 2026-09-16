rule sig_20160307_87a3bb46cfc8b2a284688ebd9eb4ae31 {
  meta:
    description = "datamaliciousorder - file 20160307_87a3bb46cfc8b2a284688ebd9eb4ae31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2388ef1c20f6042273f2312be4c95366dd8c5ca246959bf560de2e6e0af9fd6e"

  strings:
    $s1  = "keyHooks[overflowX + isReady + ajaxHandleResponses][deep + reverse]((Math.pow((matcherFromTokens, 66, jqXHR), (46 / hooks)) - (2" ascii
    $s2  = "keyHooks[overflowX + isReady + ajaxHandleResponses][deep + reverse]((Math.pow((matcherFromTokens, 66, jqXHR), (46 / hooks)) - (2" ascii
    $s3  = "parts = 19, exports = 43, setPositiveNumber = 673, backgroundClip = \"%TEMP%\", selectedIndex = 37, tokens = \".\";" fullword ascii
    $s4  = "keyHooks = ((Math.pow((10 * handleObj + 7), (iterator - 47)) - (Math.pow(xhrSupported, 2) - crossDomain)), (((1826 / removeChild" ascii
    $s5  = "keyHooks[reject + getAllResponseHeaders + ajaxHandleResponses][deep + reverse](((32572 ^ dataFilter) / (2 ^ toggle)));" fullword ascii
    $s6  = "isXMLDoc[reverse + isXML + rhash] = ((229, host, 0) | stopImmediatePropagation);" fullword ascii
    $s7  = "(Math.pow((769 ^ webkitMatchesSelector), (0 ^ _load)) - 61 * match * 5 * match * 5 * before) / ((8 | anim) * (15 - siblingCheck)" ascii
    $s8  = "clearQueue[cache + needsContext](responses + letterSpacing, cssFn + reverse + event + cached + rchecked + conv + parentWindow + " ascii
    $s9  = "delegateType = keyHooks[ajaxSetup + ajaxHandleResponses][emptyStyle + ajaxHandleResponses + qualifier + one](linear + completeDe" ascii
    $s10 = "delegateType = keyHooks[ajaxSetup + ajaxHandleResponses][emptyStyle + ajaxHandleResponses + qualifier + one](linear + completeDe" ascii
    $s11 = "while (clearQueue[mimeType + leadingRelative + matchedCount + getAttribute] < ((ignored * 0) | (val + 1))) {" fullword ascii
    $s12 = "delegateType[apply + headers](rCRLF, ((44 - eased) & (3 & val)));" fullword ascii
    $s13 = "rnoContent = 4362, swing = \"writ\", isXML = \"ositi\", xhrSupported = 3356;" fullword ascii
    $s14 = "response = keepData[emptyStyle + ajaxHandleResponses + qualifier + one](reject + nodes + tokens + to + _);" fullword ascii
    $s15 = "clearQueue = keyHooks[ajaxSetup + ajaxHandleResponses][protocol + rnotwhite + pixelPosition](onload + checkOn + delay + rparents" ascii
    $s16 = "etMatcher + _ + remaining + onerror + constructor;" fullword ascii
    $s17 = "clearQueue = keyHooks[ajaxSetup + ajaxHandleResponses][protocol + rnotwhite + pixelPosition](onload + checkOn + delay + rparents" ascii
    $s18 = "rCRLF = response[cssHooks + ajaxPrefilter + matcher + augmentWidthOrHeight + unbind + check + attrId](backgroundClip + last) + s" ascii
    $s19 = "delegateType[getter]();" fullword ascii
    $s20 = "host = 106;" fullword ascii

  condition:
    uint16(0) == 0x6e72 and
    8 of them
}