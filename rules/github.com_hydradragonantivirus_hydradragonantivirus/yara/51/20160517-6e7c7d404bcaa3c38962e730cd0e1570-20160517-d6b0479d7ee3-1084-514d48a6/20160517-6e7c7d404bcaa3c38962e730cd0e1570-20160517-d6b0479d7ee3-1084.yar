rule _20160517_6e7c7d404bcaa3c38962e730cd0e1570_20160517_d6b0479d7ee3_1084 {
  meta:
    description = "datamaliciousorder - from files 20160517_6e7c7d404bcaa3c38962e730cd0e1570.js, 20160517_d6b0479d7ee37a5d698b2c6c5bf8b84c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b875364959952e690bfc31d208b121b0cd17cdfc7475d3d99aef85021453c89"
    hash2       = "d13d8189af8d8e4a1031a62a73a332b6e4e97d62d5a8d1edc15e32fff839ee26"

  strings:
    $s1 = "var nConverts1 /* s  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* s  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* s  */;};" fullword ascii
    $s4 = "enjoy1 /* s  */ /* s  */= true;/* s  */" fullword ascii
    $s5 = "var enjoy1 /* s  */ = false;" fullword ascii
    $s6 = "batch =/* s  */ \"R\" + \"esponseB\"/* s  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s7 = "could = /* s  */(/* s  */\"noitisop\").split(''/* s  */).reverse(/* s  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}