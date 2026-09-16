rule sig_20160313_6993fa914c58333f153e1e0ac3c2d40c {
  meta:
    description = "datamaliciousorder - file 20160313_6993fa914c58333f153e1e0ac3c2d40c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae530f952f2e16c224a6e5a2dc31bb4a8f510888094b175df0f863468fb0f9a9"

  strings:
    $s1  = "copyIsArray[originalOptions + \"p\" + matchIndexes](\"GE\" + bool, \"http\" + pageX + \"ell\" + tweeners + \"q.com\" + tokens + " ascii
    $s2  = "copyIsArray[originalOptions + \"p\" + matchIndexes](\"GE\" + bool, \"http\" + pageX + \"ell\" + tweeners + \"q.com\" + tokens + " ascii
    $s3  = "rfxtypes = createDocumentFragment[fired + \"eObje\" + delegateCount](\"WScr\" + textContent + \"hel\" + qualifier);" fullword ascii
    $s4  = "resolve[\"sav\" + getBoundingClientRect + \"ile\"](fxNow, 2);" fullword ascii
    $s5  = "== ((eventPath - 15) * ((((original * 1) & (original | 0)) + (css / (67 - rts))) * (((18 - dataTypes)) * 2)) + ((((ap - 92) / (c" ascii
    $s6  = "omputed & 44)) | ((css | 0) | (original * 0))) | ((input | (13 - rinputs)) & ((1 * mouseenter)))))));" fullword ascii
    $s7  = "copyIsArray = this[\"WScr\" + filters][\"Create\" + reliableMarginLeftVal](\"MSXML\" + focus + \"HTTP\");" fullword ascii
    $s8  = "function responseHeaders() {" fullword ascii
    $s9  = "textContent = \"ipt.S\", winnow = \"se\", original = 1, isXML = 5847, timerId = \"tStri\";" fullword ascii
    $s10 = "copyIsArray[winnow + \"nd\"]();" fullword ascii
    $s11 = "resolve = this[removeEvent + \"ipt\"][dataAttr + \"Obje\" + delegateCount](\"ADODB.\" + curOffset);" fullword ascii
    $s12 = "fxNow = rfxtypes[\"Expan\" + setTimeout + \"onmen\" + timerId + \"ngs\"](xhr + \"%/\") + easing + \"entLef\" + documentIsHTML + " ascii
    $s13 = "when[originalProperties + \"e\"]();" fullword ascii
    $s14 = "createDocumentFragment = this[\"WSc\" + setGlobalEval + \"t\"];" fullword ascii
    $s15 = "nType[\"R\" + isPropagationStopped + \"n\"](fxNow, (1 * (original & 0)), ((original * 0) | (css / 26)));" fullword ascii
    $s16 = "fxNow = rfxtypes[\"Expan\" + setTimeout + \"onmen\" + timerId + \"ngs\"](xhr + \"%/\") + easing + \"entLef\" + documentIsHTML + " ascii
    $s17 = "resolve[\"op\" + matchIndexes]();" fullword ascii
    $s18 = "function tmp() {" fullword ascii
    $s19 = "function mouseleave() {" fullword ascii
    $s20 = "function initial() {" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    8 of them
}