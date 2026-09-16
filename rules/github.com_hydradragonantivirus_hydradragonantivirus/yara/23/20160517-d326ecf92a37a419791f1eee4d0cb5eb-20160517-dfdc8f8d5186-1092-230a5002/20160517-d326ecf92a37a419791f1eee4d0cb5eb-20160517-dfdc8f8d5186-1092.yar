rule _20160517_d326ecf92a37a419791f1eee4d0cb5eb_20160517_dfdc8f8d5186_1092 {
  meta:
    description = "datamaliciousorder - from files 20160517_d326ecf92a37a419791f1eee4d0cb5eb.js, 20160517_dfdc8f8d5186273fb1bfd40cd4f827f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "377e33df24dd24d25451ee0f3311b0707796a8e1a17c59f022d24823487ce199"
    hash2       = "47bf71cebc72263dd06da757e2edaa5e5a282739ef82fced6f4350c70d95ced2"

  strings:
    $s1 = "var nConverts1 /* H  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* H  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* H  */;};" fullword ascii
    $s4 = "could = /* H  */(/* H  */\"noitisop\").split(''/* H  */).reverse(/* H  */).join('');" fullword ascii
    $s5 = "var enjoy1 /* H  */ = false;" fullword ascii
    $s6 = "batch =/* H  */ \"R\" + \"esponseB\"/* H  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s7 = "enjoy1 /* H  */ /* H  */= true;/* H  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}