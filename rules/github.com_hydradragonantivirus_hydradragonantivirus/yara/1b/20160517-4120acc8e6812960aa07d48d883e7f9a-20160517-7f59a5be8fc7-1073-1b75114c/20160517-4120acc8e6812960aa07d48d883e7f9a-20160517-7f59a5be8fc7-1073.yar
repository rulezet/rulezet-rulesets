rule _20160517_4120acc8e6812960aa07d48d883e7f9a_20160517_7f59a5be8fc7_1073 {
  meta:
    description = "datamaliciousorder - from files 20160517_4120acc8e6812960aa07d48d883e7f9a.js, 20160517_7f59a5be8fc701ef5f82a550f437db9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8775e1ad63f11f0f2993d47df06afba6b5c0969ac877ca621fce868851ee8ae0"
    hash2       = "05e01127d793edaf6ee2b80ddbc5133cbb0e5e1d688e098a6e988b22b9673d67"

  strings:
    $s1 = "var nConverts1 /* c  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* c  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* c  */;};" fullword ascii
    $s4 = "batch =/* c  */ \"R\" + \"esponseB\"/* c  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s5 = "could = /* c  */(/* c  */\"noitisop\").split(''/* c  */).reverse(/* c  */).join('');" fullword ascii
    $s6 = "enjoy1 /* c  */ /* c  */= true;/* c  */" fullword ascii
    $s7 = "var enjoy1 /* c  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}