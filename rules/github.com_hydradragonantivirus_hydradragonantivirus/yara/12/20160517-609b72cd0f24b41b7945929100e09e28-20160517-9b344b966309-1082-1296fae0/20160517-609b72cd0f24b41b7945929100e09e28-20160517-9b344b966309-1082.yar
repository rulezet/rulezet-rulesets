rule _20160517_609b72cd0f24b41b7945929100e09e28_20160517_9b344b966309_1082 {
  meta:
    description = "datamaliciousorder - from files 20160517_609b72cd0f24b41b7945929100e09e28.js, 20160517_9b344b966309210b416d5f86d0887328.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "175151dfaf640c16e7fa7d150510ee60d5f0aa3337e788bfe37ac7346da096a4"
    hash2       = "0d5d44e17f6b59e2245953f74d89340bee1ce9488fac9c0cc6084c9d271f2b84"

  strings:
    $s1 = "var nConverts1 /* q  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* q  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* q  */;};" fullword ascii
    $s4 = "enjoy1 /* q  */ /* q  */= true;/* q  */" fullword ascii
    $s5 = "batch =/* q  */ \"R\" + \"esponseB\"/* q  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "var enjoy1 /* q  */ = false;" fullword ascii
    $s7 = "could = /* q  */(/* q  */\"noitisop\").split(''/* q  */).reverse(/* q  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}