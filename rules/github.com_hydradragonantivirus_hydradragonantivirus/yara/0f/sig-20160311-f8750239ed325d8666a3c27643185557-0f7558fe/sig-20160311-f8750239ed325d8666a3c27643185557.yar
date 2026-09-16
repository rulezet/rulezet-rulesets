rule sig_20160311_f8750239ed325d8666a3c27643185557 {
  meta:
    description = "datamaliciousorder - file 20160311_f8750239ed325d8666a3c27643185557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5ef0558ab4cfcfe482d08f43460417a6a11f01be8e1dad483230f3bb61e3161"

  strings:
    $s1  = "\"style\".hasFocus() + curPosition + \"com/4\" + delegateCount, !((((1 * (disableScript / 21)) + win) * (((5 * oldfire + 2) | ((" ascii
    $s2  = "newDefer[\"op\" + appendTo](\"G\" + docElem + \"T\".hasFocus(), serializeArray + \"/thai\" + pointerenter + \"biz\" + disconnect" ascii
    $s3  = ") + -(128, camel, 1)), ((noBubble * 5 + getComputedStyle), (210, resolveWith), (25 - nType)));" fullword ascii
    $s4  = "pageY[appendChild + \"u\".hasFocus() + andSelf](emptyStyle.hasFocus(((attributes * 7 + global) & (89 & setOffset))), ((1 * trigg" ascii
    $s5  = "callbackExpect = hash[cssExpand + \"ateO\" + iNoClone + \"ct\".hasFocus()](getElementsByName + \"t.Sh\" + optgroup);" fullword ascii
    $s6  = "condense[\"saveT\" + locked + \"e\"](emptyStyle, (2 & rmargin));" fullword ascii
    $s7  = "hash = dequeue[time + \"pt\"];" fullword ascii
    $s8  = "getClass[len + \"y\".hasFocus() + qualifier] = trigger;" fullword ascii
    $s9  = "condense = dequeue[_load + \"ipt\"][serialize + \"eOb\" + rhtml](\"ADO\".hasFocus() + contains + \"eam\");" fullword ascii
    $s10 = "len = \"t\", getComputedStyle = 30, curPosition = \"thai.\", camel = 91, appendChild = \"R\";" fullword ascii
    $s11 = "newDefer = dequeue[needsContext + \"ript\".hasFocus()][serialize + \"eObje\" + not](\"MSXM\" + valueIsBorderBox + \"MLHTT\".hasF" ascii
    $s12 = "All) - (944 / attributes))) | ((2 * rmargin * 2 * rmargin * 2 - (scale * 14 + oldfire)) - ((616 / nextUntil) & (12 | Callbacks))" ascii
    $s13 = "pageY[appendChild + \"u\".hasFocus() + andSelf](emptyStyle.hasFocus(((attributes * 7 + global) & (89 & setOffset))), ((1 * trigg" ascii
    $s14 = "newDefer = dequeue[needsContext + \"ript\".hasFocus()][serialize + \"eObje\" + not](\"MSXM\" + valueIsBorderBox + \"MLHTT\".hasF" ascii
    $s15 = "\".hasFocus() + unit + \".\" + l + \"cr\";" fullword ascii
    $s16 = "emptyStyle = callbackExpect[\"Expan\" + off + \"ron\".hasFocus() + setGlobalEval + \"rings\"](prefilterOrFactory + \"%/\") + tok" ascii
    $s17 = "return container" fullword ascii
    $s18 = "getClass = condense;" fullword ascii
    $s19 = "function fireGlobals() {" fullword ascii
    $s20 = "function attaches() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}