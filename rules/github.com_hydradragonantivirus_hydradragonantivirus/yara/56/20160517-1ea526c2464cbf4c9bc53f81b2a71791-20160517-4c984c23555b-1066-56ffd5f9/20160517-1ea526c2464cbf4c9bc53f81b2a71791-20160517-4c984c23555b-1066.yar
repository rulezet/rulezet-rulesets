rule _20160517_1ea526c2464cbf4c9bc53f81b2a71791_20160517_4c984c23555b_1066 {
  meta:
    description = "datamaliciousorder - from files 20160517_1ea526c2464cbf4c9bc53f81b2a71791.js, 20160517_4c984c23555b03b2ba8045d90ca30f59.js, 20160517_82789bef7fa7576887766d4bed9b6ea0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91309d02f635d130c3942b7d401fb0db2f7c15d3048d8238eb21196772738499"
    hash2       = "da80f526dde7649f4f07e277607468b8a5a2643c8ca951d262d008e2970799d7"
    hash3       = "0828853dd56909666b00aa0c37b27606dcd888939238a3ca049709b208f8c5ec"

  strings:
    $s1 = "var nConverts1 /* k  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* k  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* k  */;};" fullword ascii
    $s4 = "var enjoy1 /* k  */ = false;" fullword ascii
    $s5 = "enjoy1 /* k  */ /* k  */= true;/* k  */" fullword ascii
    $s6 = "batch =/* k  */ \"R\" + \"esponseB\"/* k  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s7 = "could = /* k  */(/* k  */\"noitisop\").split(''/* k  */).reverse(/* k  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}