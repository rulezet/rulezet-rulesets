rule sig_20160313_040a8f9d89fe9cc1937f762e5ff87190 {
  meta:
    description = "datamaliciousorder - file 20160313_040a8f9d89fe9cc1937f762e5ff87190.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb775c2e1f63186ad28e8440ce451d7ae6df6b6554e6868c6368cfd2b0e7f921"

  strings:
    $x1  = "duration[rquickExpr + \"e\" + getText](\"GE\" + siblings, \"http:\" + compareDocumentPosition + \"log\" + addCombinator + \"q.co" ascii
    $x2  = "duration[rquickExpr + \"e\" + getText](\"GE\" + siblings, \"http:\" + compareDocumentPosition + \"log\" + addCombinator + \"q.co" ascii
    $s3  = "ition + \"e\", !((Math.pow((3 * (computed, 119, accepts, 2) + getElementsByClassName), (((70 + sibling), (Math.pow(44, body) - 1" ascii
    $s4  = "Math.pow(5, body) - 18) | rparentsprev) + (14 / dataShow)) | ((Math.pow((16 | showHide), (2 + showHide)) - (339 - handlers)) + (" ascii
    $s5  = "rCRLF = this[hasCompare + \"ript\"][relatedTarget + \"eObj\" + trigger](\"ADODB\" + slow + \"eam\");" fullword ascii
    $s6  = " 24) | (dataFilter * 8)), ((appendTo | 8) - (Math.pow(risSimple, 2) - simulate))) + ((50 - fontWeight) * 2 + getElementsByClassN" ascii
    $s7  = "7 * body * 31 / (animate / 46))))) == (((((removeAttr + 71) | (Math.pow(addBack, 2) - params)), (19 * dataFilter + 13), ((etag +" ascii
    $s8  = "relatedTarget = (function el() {}, \"Creat\");" fullword ascii
    $s9  = "function requestHeadersNames() {" fullword ascii
    $s10 = "notify[\"ty\" + requestHeaders + \"e\"] = (getElementsByClassName | (178, argument, 128, showHide));" fullword ascii
    $s11 = "offsetHeight = this[\"WSc\" + bup];" fullword ascii
    $s12 = "duration = this[cloneNode + \"ipt\"][boolHook + \"teObje\" + curPosition](\"MSXML\" + markFunction + \"TTP\");" fullword ascii
    $s13 = "duration[resolveWith + \"nd\"]();" fullword ascii
    $s14 = "rejectWith = offsetHeight[\"Create\" + tween + \"t\"](parseHTML + \"pt.S\" + minWidth);" fullword ascii
    $s15 = "function readyList() {" fullword ascii
    $s16 = "slow = \".Str\";" fullword ascii
    $s17 = "rCRLF[parse + \"oFile\"](dataUser, body);" fullword ascii
    $s18 = "setGlobalEval = (function el.rcomma() {" fullword ascii
    $s19 = "computed = 245, handlers = 108, simulate = 459, parse = \"saveT\";" fullword ascii
    $s20 = "function dataPriv() {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}