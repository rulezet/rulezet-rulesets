rule _20160517_20e9e4cbc7aa888aee9ee20888966a1d_20160517_4c6154e38ad4_1068 {
  meta:
    description = "datamaliciousorder - from files 20160517_20e9e4cbc7aa888aee9ee20888966a1d.js, 20160517_4c6154e38ad40286507812e7ca1bfa4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbfef6a83d3bcdbc553d6c7dd097e92fa0a7372af890fe726e2b52a8310b5f62"
    hash2       = "43dfdf6bd594d735f7cc1abbc9bff405e8b596126e31126cd92a1dabe8b0bb30"

  strings:
    $s1 = "var nConverts1 /* n  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* n  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* n  */;};" fullword ascii
    $s4 = "could = /* n  */(/* n  */\"noitisop\").split(''/* n  */).reverse(/* n  */).join('');" fullword ascii
    $s5 = "batch =/* n  */ \"R\" + \"esponseB\"/* n  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "var enjoy1 /* n  */ = false;" fullword ascii
    $s7 = "enjoy1 /* n  */ /* n  */= true;/* n  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}