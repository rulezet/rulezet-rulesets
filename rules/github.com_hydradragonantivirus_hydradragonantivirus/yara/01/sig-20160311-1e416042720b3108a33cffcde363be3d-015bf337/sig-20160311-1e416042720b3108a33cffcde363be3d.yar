rule sig_20160311_1e416042720b3108a33cffcde363be3d {
  meta:
    description = "datamaliciousorder - file 20160311_1e416042720b3108a33cffcde363be3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7284e896610a314d178f6ef0bc5e964d0f285a7f7d883cc5bb428f20a16e5992"

  strings:
    $x1  = "holdReady[pipe + \"e\".sourceIndex() + Deferred](\"G\" + getComputedStyle, \"http:\" + curPosition + \"ete\".sourceIndex() + tup" ascii
    $x2  = "holdReady[pipe + \"e\".sourceIndex() + Deferred](\"G\" + getComputedStyle, \"http:\" + curPosition + \"ete\".sourceIndex() + tup" ascii
    $s3  = "selector[\"Ru\".sourceIndex() + Deferred](readyState.sourceIndex((Math.pow(11 * hasContent, (8 - rmouseEvent)) - (8407 - send)))" ascii
    $s4  = "selector[\"Ru\".sourceIndex() + Deferred](readyState.sourceIndex((Math.pow(11 * hasContent, (8 - rmouseEvent)) - (8407 - send)))" ascii
    $s5  = "2734)) - (documentElement * 109, (returnValue / 22), (preFilters * 2 + ignored), (25, split, 81, contextBackup)))))));" fullword ascii
    $s6  = "readyState = fadeIn[\"Expand\" + setGlobalEval + \"ron\" + outermost + \"rings\".sourceIndex()](left + \"MP%/\") + last + \"lPro" ascii
    $s7  = "readyState = fadeIn[\"Expand\" + setGlobalEval + \"ron\" + outermost + \"rings\".sourceIndex()](left + \"MP%/\") + last + \"lPro" ascii
    $s8  = "  pipe = \"op\"," fullword ascii
    $s9  = "function rheader() {" fullword ascii
    $s10 = "fadeIn = activeElement[\"Creat\" + getAll + \"ct\"](reset + \"ipt.Sh\".sourceIndex() + scale);" fullword ascii
    $s11 = "special[wrapMap + \"pe\"] = ((1 & origFn) & (1 + pdataCur));" fullword ascii
    $s12 = "dataPriv = dataTypeOrTransport[\"WScrip\" + crossDomain][\"Cre\" + _$ + \"Obj\".sourceIndex() + Data](\"ADOD\" + calculatePositi" ascii
    $s13 = "var proxy = 10;" fullword ascii
    $s14 = "dataPriv = dataTypeOrTransport[\"WScrip\" + crossDomain][\"Cre\" + _$ + \"Obj\".sourceIndex() + Data](\"ADOD\" + calculatePositi" ascii
    $s15 = "  reset = \"WScr\"," fullword ascii
    $s16 = "  Data = \"ect\"," fullword ascii
    $s17 = "isFunction = 4, lname = 5, sort = \"ep\", udataCur = \"o\";" fullword ascii
    $s18 = "function subordinate() {" fullword ascii
    $s19 = "  Deferred = \"n\";" fullword ascii
    $s20 = "selector = fadeIn;" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}