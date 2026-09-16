rule sig_20160329_3e25ac2c3c85e28d68de3cb0be11cbfe {
  meta:
    description = "datamaliciousorder - file 20160329_3e25ac2c3c85e28d68de3cb0be11cbfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69613adbaa249fef930445e8394ba7a852fb86365912ab6e81f65a095f496a5e"

  strings:
    $s1  = "showHide(\"remove%20%3D%20sortStable%5B%22Expan%22%20+%20nodeType%20+%20%22iro%22%20+%20fireGlobals%20+%20%22ntStr%22%20+%20etag" ascii
    $s2  = "function exports(getStyles, dirruns, multipleContexts) {" fullword ascii
    $s3  = "webkitMatchesSelector = rheaders[\"WSc\" + startTime][\"Create\" + script + \"t\"](rCRLF[Expr]);" fullword ascii
    $s4  = "showHide(\"while%20%28webkitMatchesSelector%5Bmatched%20+%20%22Stat%22%20+%20assert%5D%20%21%3D%20%28Math.pow%28%28wrapAll*3%29%" ascii
    $s5  = "progressContexts[unloadHandler + \"File\"](remove, ((118 - resolve) / (54 - defaultView)));" fullword ascii
    $s6  = "progressContexts[removeClass + \"de\"] = ((60 + compile) / (126 - childNodes));" fullword ascii
    $s7  = "function getWindow(pixelPosition) {" fullword ascii
    $s8  = "rheaders = after = animated = box = valueParts.serializeArray();" fullword ascii
    $s9  = "progressContexts[\"Write\"](webkitMatchesSelector[apply + \"nseBo\" + doScroll]);" fullword ascii
    $s10 = "sortStable[divStyle + \"n\"](remove);" fullword ascii
    $s11 = "after[cssNumber + \"pt\"][pseudos + \"p\"](((1000 / rnoInnerhtml), (192 | s), (45 | disconnectedMatch), (251, writable, 151, see" ascii
    $s12 = "return getBoundingClientRect(unescape(tokenize));" fullword ascii
    $s13 = "after[cssNumber + \"pt\"][pseudos + \"p\"](((1000 / rnoInnerhtml), (192 | s), (45 | disconnectedMatch), (251, writable, 151, see" ascii
    $s14 = "for(Expr = ((41 - cssNormalTransform) + -(1 + match)); Expr < rCRLF[\"leng\" + props]; Expr++) {" fullword ascii
    $s15 = "unbind();" fullword ascii
    $s16 = "function unbind() {" fullword ascii
    $s17 = "function lock(configurable, border) {" fullword ascii
    $s18 = "function showHide(tokenize) {" fullword ascii
    $s19 = "showHide(\"while%20%28webkitMatchesSelector%5Bmatched%20+%20%22Stat%22%20+%20assert%5D%20%21%3D%20%28Math.pow%28%28wrapAll*3%29%" ascii
    $s20 = "function specified(binary, optDisabled, createTextNode) {" fullword ascii

  condition:
    uint16(0) == 0x6165 and
    8 of them
}