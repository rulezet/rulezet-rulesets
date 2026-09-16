rule _20160517_4ae597ee7ad288987c621e07d1d8209a_20160517_5435d2e6809d_1077 {
  meta:
    description = "datamaliciousorder - from files 20160517_4ae597ee7ad288987c621e07d1d8209a.js, 20160517_5435d2e6809d3dd5799ebd3ce60d5977.js, 20160517_bce96c45aff3700c482fca472b344b60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af0323968192955411714a0128796ecbb40bb6cfd292f22f26cc6a0b41003e59"
    hash2       = "5d6fac3bb2483539fe49097a4fddf907692ccc4e805cf157995db258503300e9"
    hash3       = "750b578a5bc04d5cdfc5567664ba98e4398d335cff77003fa59697b478f52bf8"

  strings:
    $s1 = "var nConverts1 /* Y  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* Y  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* Y  */;};" fullword ascii
    $s4 = "batch =/* Y  */ \"R\" + \"esponseB\"/* Y  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s5 = "var enjoy1 /* Y  */ = false;" fullword ascii
    $s6 = "could = /* Y  */(/* Y  */\"noitisop\").split(''/* Y  */).reverse(/* Y  */).join('');" fullword ascii
    $s7 = "enjoy1 /* Y  */ /* Y  */= true;/* Y  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}