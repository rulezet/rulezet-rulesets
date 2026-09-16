rule sig_20160329_d91b2c7a2d4a2e8d832fcdab6052774f {
  meta:
    description = "datamaliciousorder - file 20160329_d91b2c7a2d4a2e8d832fcdab6052774f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f55920e7f315ee0c3a13b0181f640d7b86cfe7656fbe5d6027204705f999e82"

  strings:
    $s1  = "   if(resolve[progress + \"us\"] == ((235 & restoreScript) - (1 * pattern))) {" fullword ascii
    $s2  = "Data[\"t\" + file + \"pe\"] = ((1 & xml) & (26 / addToPrefiltersOrTransports));" fullword ascii
    $s3  = "   byElement(\"Data%20%3D%20ct%5B%22WScri%22%20+%20sibling%5D%5B%22Creat%22%20+%20getScript%20+%20%22ct%22%5D%28fix%20+%20%22Str" ascii
    $s4  = "function get() {" fullword ascii
    $s5  = "get(noop, grep, isNumeric, toArray, sibling);" fullword ascii
    $s6  = "   byElement(\"Data%20%3D%20ct%5B%22WScri%22%20+%20sibling%5D%5B%22Creat%22%20+%20getScript%20+%20%22ct%22%5D%28fix%20+%20%22Str" ascii
    $s7  = "function startLength(getWindow, unquoted, backgroundClip) {" fullword ascii
    $s8  = "      getBoundingClientRect[removeAttr + \"n\"](param);" fullword ascii
    $s9  = "function username(box) {" fullword ascii
    $s10 = "      ct[\"WSc\" + grep + \"t\"][removeEvent + \"ep\"]((7753 - (promise - 2591)));" fullword ascii
    $s11 = "      Data[\"Sav\" + version + \"Fil\" + marginLeft](param, (2 & excess));" fullword ascii
    $s12 = "   byElement(\"resolve%5B%22op%22%20+%20marginLeft%20+%20%22n%22%5D%28matches%20+%20%22T%22%2C%20reverse%20+%20%22//fo%22%20+%20" ascii
    $s13 = "function sortDetached() {" fullword ascii
    $s14 = "function parents() {" fullword ascii
    $s15 = "function sel() {" fullword ascii
    $s16 = "function originAnchor(optSelected, groups) {" fullword ascii
    $s17 = "window = filter = ct = expand = clearInterval.result();" fullword ascii
    $s18 = "function conv(ret, cssNumber) {" fullword ascii
    $s19 = "function rparentsprev(radio) {" fullword ascii
    $s20 = "   byElement(\"Data%5B%22W%22%20+%20styles%5D%28resolve%5B%22res%22%20+%20getElementById%20+%20%22seBo%22%20+%20each%5D%29%3B\")" ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}