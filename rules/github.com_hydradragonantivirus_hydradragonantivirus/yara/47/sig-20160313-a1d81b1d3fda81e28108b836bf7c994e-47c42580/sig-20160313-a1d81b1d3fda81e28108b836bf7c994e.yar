rule sig_20160313_a1d81b1d3fda81e28108b836bf7c994e {
  meta:
    description = "datamaliciousorder - file 20160313_a1d81b1d3fda81e28108b836bf7c994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fcea708dcd07ae9782cb933765a876276c190caf5ea3d81aa77bc9e3708ec03"

  strings:
    $s1  = "wrapMap[\"op\" + parseJSON](\"G\" + firstElementChild, \"htt\" + prevUntil + \"ellog\" + contentType + \"om/70.\" + getClientRec" ascii
    $s2  = "wrapMap = this[stopPropagation + \"t\"][extra + \"teOb\" + defaultExtra](\"MSXM\" + target + \"MLHTT\" + attributes);" fullword ascii
    $s3  = "rxhtmlTag = isPropagationStopped[\"Exp\" + jsonpCallback + \"ironme\" + delegateCount + \"ing\" + elementMatcher](\"%TEMP%\" + w" ascii
    $s4  = "(clearInterval * 2)) - isSimulated)) | (((506 - show) / 19) & (Math.pow((nodeNameSelector & 7), (leadingRelative + 0)) - (pageXO" ascii
    $s5  = "rxhtmlTag = isPropagationStopped[\"Exp\" + jsonpCallback + \"ironme\" + delegateCount + \"ing\" + elementMatcher](\"%TEMP%\" + w" ascii
    $s6  = "target = \"L2.X\", clearInterval = 1;" fullword ascii
    $s7  = "/ 39), (preexisting + 99), clearTimeout, 1))) * ((((state, 181, transport, 11) + (clearInterval + 10)), (Math.pow((always | 8), " ascii
    $s8  = "elementMatcher = (function onerror.thead() {" fullword ascii
    $s9  = "rts[speed + \"Fil\" + _removeData](rxhtmlTag, ((13 - marginDiv) * (2 | css)));" fullword ascii
    $s10 = "merge[\"R\" + dataAndEvents + \"n\"](rxhtmlTag, ((fadeIn & 46) - (fadeIn & 63)), ((marginDiv - 12) & (pageXOffset - 9)));" fullword ascii
    $s11 = "rts = this[stopPropagation + \"t\"][qualifier + \"ateObj\" + len](\"ADODB\" + token + \"ream\");" fullword ascii
    $s12 = "first[\"clos\" + _removeData]();" fullword ascii
    $s13 = "allTypes = this[\"WScrip\" + rattributeQuotes];" fullword ascii
    $s14 = "cssNormalTransform = (function onerror() {}, \"y\");" fullword ascii
    $s15 = "var token = \".St\"," fullword ascii
    $s16 = "transport = 209," fullword ascii
    $s17 = "function ajaxHandleResponses() {" fullword ascii
    $s18 = "function responseText() {" fullword ascii
    $s19 = "function orig() {" fullword ascii
    $s20 = "var optall = this;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}