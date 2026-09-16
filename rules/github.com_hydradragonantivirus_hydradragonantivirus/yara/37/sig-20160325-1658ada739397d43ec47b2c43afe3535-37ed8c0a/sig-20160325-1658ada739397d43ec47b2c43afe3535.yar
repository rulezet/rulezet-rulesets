rule sig_20160325_1658ada739397d43ec47b2c43afe3535 {
  meta:
    description = "datamaliciousorder - file 20160325_1658ada739397d43ec47b2c43afe3535.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8236d166a37c605220f609744f7884c4851bea3399b950e633acf8aa4687cbc"

  strings:
    $s1  = "var timeout = \"%TEMP%\"," fullword ascii
    $s2  = "keepData[time + \"leep\"](((responseText & 4091) * (support - 18) + (createHTMLDocument / 2)));" fullword ascii
    $s3  = "    eval(dataAndEvents(\"module%5Bmodified%20+%20%22en%22%5D%28pipe%20+%20%22E%22%20+%20addEventListener%2C%20%22http%3A%22%20+%" ascii
    $s4  = "var password = \"pe\";;" fullword ascii
    $s5  = "    boolHook[\"ty\" + password] = ((allTypes | 1) * allTypes);" fullword ascii
    $s6  = "pipe = \"G\";" fullword ascii
    $s7  = "function addGetHookIf() {" fullword ascii
    $s8  = "module[\"s\" + clientX + \"d\"]();" fullword ascii
    $s9  = "    eval(dataAndEvents(\"module%5Bmodified%20+%20%22en%22%5D%28pipe%20+%20%22E%22%20+%20addEventListener%2C%20%22http%3A%22%20+%" ascii
    $s10 = "elemData = anim[\"Expan\" + checkDisplay + \"vir\" + properties + \"entS\" + Deferred + \"ngs\"](timeout + \"/\") + curTop + \"." ascii
    $s11 = "elemData = anim[\"Expan\" + checkDisplay + \"vir\" + properties + \"entS\" + Deferred + \"ngs\"](timeout + \"/\") + curTop + \"." ascii
    $s12 = "    rbuggyMatches(byElement, resolve, Deferred, addEventListener, thead);" fullword ascii
    $s13 = "support = 20;" fullword ascii
    $s14 = "tfoot(linear, Expr, callbackExpect, emptyGet, rbuggyQSA);" fullword ascii
    $s15 = "thead = (function className() {}, 171), tag = \"pt\", responseText = 2495, emptyGet = (function className.colgroup() {" fullword ascii
    $s16 = "time = \"S\";" fullword ascii
    $s17 = "function parentNode() {" fullword ascii
    $s18 = "function maxIterations() {" fullword ascii
    $s19 = "function _evalUrl() {" fullword ascii
    $s20 = "function parseFromString() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}