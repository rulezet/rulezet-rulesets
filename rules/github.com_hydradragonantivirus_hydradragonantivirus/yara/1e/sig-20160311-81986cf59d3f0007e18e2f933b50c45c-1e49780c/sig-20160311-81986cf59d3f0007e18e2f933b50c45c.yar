rule sig_20160311_81986cf59d3f0007e18e2f933b50c45c {
  meta:
    description = "datamaliciousorder - file 20160311_81986cf59d3f0007e18e2f933b50c45c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19f9fd2c2ff9bd883c7384c98857d086d8f40655e98551c312fbf6071b020e47"

  strings:
    $s1  = "originalSettings[\"save\" + headers + \"le\"](delay, ((23 - nodeValue) | 2));" fullword ascii
    $s2  = "left = (((44, rhash) & (10 * innerText + 5)), ((width - 60) - (isArrayLike | 9)), eval(\"th\" + dispatch + \"s\".serializeArray(" ascii
    $s3  = "rclass[offsetParent + \"e\" + excess](\"G\" + fail + \"T\".serializeArray(), clientLeft + \"//s\" + reliableMarginRight + \"yofi" ascii
    $s4  = "letter = \"s.com/\", m = \"WScri\";" fullword ascii
    $s5  = "delay = self[fnOut + \"Envir\" + postDispatch + \"tStrin\".serializeArray() + guaranteedUnique](\"%TEM\" + checkContext) + \"rsu" ascii
    $s6  = "realStringObj[\"t\" + converters + \"pe\".serializeArray()] = ((9 / token) + (7, len));" fullword ascii
    $s7  = "rclass = left[nodeName + \"ipt\".serializeArray()][doAnimation + \"Objec\" + height](\"MSX\" + addCombinator + \"LHTTP\".seriali" ascii
    $s8  = "rclass = left[nodeName + \"ipt\".serializeArray()][doAnimation + \"Objec\" + height](\"MSX\" + addCombinator + \"LHTTP\".seriali" ascii
    $s9  = "delay = self[fnOut + \"Envir\" + postDispatch + \"tStrin\".serializeArray() + guaranteedUnique](\"%TEM\" + checkContext) + \"rsu" ascii
    $s10 = "self = rwhitespace[doAnimation + \"Obje\" + conv](\"WScri\".serializeArray() + parseJSON + \"hell\");" fullword ascii
    $s11 = "originalSettings[attrHooks + \"pe\" + excess]();" fullword ascii
    $s12 = "rwhitespace = left[nodeName + \"ipt\"];" fullword ascii
    $s13 = "originalSettings = left[m + \"pt\".serializeArray()][needsContext + \"eObje\" + conv](\"ADO\" + remaining + \"Stream\".serialize" ascii
    $s14 = "originalSettings = left[m + \"pt\".serializeArray()][needsContext + \"eObje\" + conv](\"ADO\" + remaining + \"Stream\".serialize" ascii
    $s15 = "token = 9;" fullword ascii
    $s16 = "rclass[offsetParent + \"e\" + excess](\"G\" + fail + \"T\".serializeArray(), clientLeft + \"//s\" + reliableMarginRight + \"yofi" ascii
    $s17 = "}, \"bmi\"), checkContext = \"P%/\", fail = \"E\";" fullword ascii
    $s18 = "excess = \"n\";" fullword ascii
    $s19 = "function mouseleave() {" fullword ascii
    $s20 = "function stopImmediatePropagation() {" fullword ascii

  condition:
    uint16(0) == 0x6872 and
    8 of them
}