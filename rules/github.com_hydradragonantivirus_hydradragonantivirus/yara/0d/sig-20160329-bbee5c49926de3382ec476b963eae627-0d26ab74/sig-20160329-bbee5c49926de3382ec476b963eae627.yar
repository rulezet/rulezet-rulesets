rule sig_20160329_bbee5c49926de3382ec476b963eae627 {
  meta:
    description = "datamaliciousorder - file 20160329_bbee5c49926de3382ec476b963eae627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62a444396d5ef52f22cd3088a7b370c4b404b3e9c2b2724adfe2d088e029cba9"

  strings:
    $s1  = "needsContext(\"offset%5B%22op%22%20+%20once%20+%20%22n%22%5D%28scrollTo%20+%20%22T%22%2C%20div%20+%20%22%3A//hot%22%20+%20reliab" ascii
    $s2  = "needsContext(\"while%20%28offset%5B%22readyS%22%20+%20attributes%5D%20%21%3D%20%28%28200%2C_jQuery%2C4%29%7Crclickable%29%29%20s" ascii
    $s3  = "needsContext(\"name%20%3D%20contexts%5BfirstElementChild%20+%20%22dEnvi%22%20+%20excess%20+%20%22entSt%22%20+%20rkeyEvent%20+%20" ascii
    $s4  = "needsContext(\"name%20%3D%20contexts%5BfirstElementChild%20+%20%22dEnvi%22%20+%20excess%20+%20%22entSt%22%20+%20rkeyEvent%20+%20" ascii
    $s5  = "clientY[success + \"p\" + once] = (compare + 0);" fullword ascii
    $s6  = "function rsingleTag(pnum, disableScript, cssProps) {" fullword ascii
    $s7  = "offset = restoreScript[stopped + \"pt\"][removeData + \"teObje\" + overflow](bup[jsonpCallback]);" fullword ascii
    $s8  = "getAttributeNode(removeProp, unique, guaranteedUnique, defineProperty);" fullword ascii
    $s9  = "function getAttributeNode(clazz, winnow, parsed) {" fullword ascii
    $s10 = "rsingleTag(beforeSend, timeout, forward, defineProperty, excess);" fullword ascii
    $s11 = "border(forward);" fullword ascii
    $s12 = "if (offset[documentIsHTML] == ((rclass - 23) * (value - 46) * (curCSS) * (5 & curCSS) * (2 + rclickable))) {" fullword ascii
    $s13 = "contexts[\"Ru\" + fxNow](name);" fullword ascii
    $s14 = "offset[uniqueID + \"e\" + udataOld]();" fullword ascii
    $s15 = "needsContext(\"while%20%28offset%5B%22readyS%22%20+%20attributes%5D%20%21%3D%20%28%28200%2C_jQuery%2C4%29%7Crclickable%29%29%20s" ascii
    $s16 = "} catch (rscriptType) {" fullword ascii
    $s17 = "return responseHeaders(unescape(hold));" fullword ascii
    $s18 = "function maxWidth() {" fullword ascii
    $s19 = "function border() {" fullword ascii
    $s20 = "function ajaxExtend() {" fullword ascii

  condition:
    uint16(0) == 0x6877 and
    8 of them
}