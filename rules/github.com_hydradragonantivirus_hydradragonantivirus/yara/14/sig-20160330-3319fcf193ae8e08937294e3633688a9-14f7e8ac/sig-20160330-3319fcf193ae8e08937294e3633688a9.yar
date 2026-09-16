rule sig_20160330_3319fcf193ae8e08937294e3633688a9 {
  meta:
    description = "datamaliciousorder - file 20160330_3319fcf193ae8e08937294e3633688a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b1302dcfda89df146dd712cc4eaeb039c59503d0e46e5def6c8b9d512755fa5"

  strings:
    $s1  = "on[\"mo\" + pixelPositionVal] = ((Math.pow(50, submit) - 2440) / (originAnchor));" fullword ascii
    $s2  = "letterSpacing(\"outermost&5BstatusText&20+&20&22pt&22&5D&5Bparent&20+&20&22lee&22&20+&20doc&5D&28&28&28curOffset/12&29*&28checkb" ascii
    $s3  = "risSimple(username, doc, thead, simple, add);" fullword ascii
    $s4  = "evt[run + \"ipt\"][boolHook](((597 * events + 557) | (global, 4360)));" fullword ascii
    $s5  = "firstDataType(thead, text, propFilter, simple);" fullword ascii
    $s6  = "function idx(setRequestHeader) {" fullword ascii
    $s7  = "function firstDataType(parseHTML, getWidthOrHeight, parentNode) {" fullword ascii
    $s8  = "function ajaxTransport() {" fullword ascii
    $s9  = "function rootjQuery() {" fullword ascii
    $s10 = "if (callbackInverse[\"stat\" + noConflict] == ((22 + truncate) | (132, setPositiveNumber))) {" fullword ascii
    $s11 = "function letterSpacing(exports) {" fullword ascii
    $s12 = "letterSpacing(\"while&20&28callbackInverse&5B&22readyS&22&20+&20bup&5D&20&21&3D&20&28Math.pow&28&28boxSizingReliableVal/50&29&2C" ascii
    $s13 = "letterSpacing(\"while&20&28callbackInverse&5B&22readyS&22&20+&20bup&5D&20&21&3D&20&28Math.pow&28&28boxSizingReliableVal/50&29&2C" ascii
    $s14 = "urlAnchor(udataOld, add, parent, len);" fullword ascii
    $s15 = "evt = outermost = matchesSelector = throws = charset.l();" fullword ascii
    $s16 = "function risSimple(firing) {" fullword ascii
    $s17 = "function msMatchesSelector(one) {" fullword ascii
    $s18 = "function documentIsHTML(fxNow, parseFromString) {" fullword ascii
    $s19 = "function clearTimeout(superMatcher, removeAttribute) {" fullword ascii
    $s20 = "letterSpacing(\"outermost&5BstatusText&20+&20&22pt&22&5D&5Bparent&20+&20&22lee&22&20+&20doc&5D&28&28&28curOffset/12&29*&28checkb" ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}