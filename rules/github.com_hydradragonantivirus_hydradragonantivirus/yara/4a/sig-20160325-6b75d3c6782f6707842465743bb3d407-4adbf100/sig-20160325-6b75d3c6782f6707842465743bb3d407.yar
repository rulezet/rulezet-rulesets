rule sig_20160325_6b75d3c6782f6707842465743bb3d407 {
  meta:
    description = "datamaliciousorder - file 20160325_6b75d3c6782f6707842465743bb3d407.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e11e1d6c5467a55af337ce8d99577f06e38968125638f3adab88af5a3c900c"

  strings:
    $s1  = "submit = prevAll[elem + \"ndE\" + getAllResponseHeaders + \"ment\" + boolHook + \"gs\"](tweeners + \"P%/\") + computeStyleTests " ascii
    $s2  = "getAttributeNode = \"T\", token = \"rt\", keepScripts = (function checkOn.maxIterations() {" fullword ascii
    $s3  = "getResponseHeader[\"WScr\" + progressValues][\"Sl\" + optSelected](((20447 - current) - (2231 & state)));" fullword ascii
    $s4  = "submit = prevAll[elem + \"ndE\" + getAllResponseHeaders + \"ment\" + boolHook + \"gs\"](tweeners + \"P%/\") + computeStyleTests " ascii
    $s5  = "function processData() {" fullword ascii
    $s6  = "eval(accepts(\"flag%28submit%2C%20onreadystatechange%2C%20%28%28sel%261%29*getText%29%2C%20pop%20+%20%22ToFil%22%20+%20keepScrip" ascii
    $s7  = "eval(accepts(\"flag%28submit%2C%20onreadystatechange%2C%20%28%28sel%261%29*getText%29%2C%20pop%20+%20%22ToFil%22%20+%20keepScrip" ascii
    $s8  = " keepScripts + \".\" + type + \"cr\";" fullword ascii
    $s9  = "run = 12, statusCode = \"otype\", getText = 2, unique = \"/kant\";" fullword ascii
    $s10 = "once[\"Sl\" + subtract + \"p\"](((readyWait / 19) | (defer)));" fullword ascii
    $s11 = "var document = [][\"const\" + obj][\"prot\" + statusCode][\"so\" + token][\"apply\"]();" fullword ascii
    $s12 = "pop = \"save\", param = \"ose\", rcomma = \"n\", addEventListener = \"ject\", state = 3327;" fullword ascii
    $s13 = "extra(rcleanScript, col);" fullword ascii
    $s14 = "parentNode = prev = getResponseHeader = bool = checkOn.maxIterations();" fullword ascii
    $s15 = "prevAll = once[\"Crea\" + isArray + \"bjec\" + progressContexts](\"WScrip\" + dequeue + \"l\");" fullword ascii
    $s16 = "once = bool[\"WScr\" + progressValues];" fullword ascii
    $s17 = "to[\"cl\" + param]();" fullword ascii
    $s18 = "disabled(statusCode, elem, readyWait, boolHook);" fullword ascii
    $s19 = "function risSimple() {" fullword ascii
    $s20 = "function pageXOffset() {" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}