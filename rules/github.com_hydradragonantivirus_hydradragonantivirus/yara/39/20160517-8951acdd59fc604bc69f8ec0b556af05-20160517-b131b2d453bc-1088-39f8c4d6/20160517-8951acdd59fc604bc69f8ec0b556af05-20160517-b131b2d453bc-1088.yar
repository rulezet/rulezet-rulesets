rule _20160517_8951acdd59fc604bc69f8ec0b556af05_20160517_b131b2d453bc_1088 {
  meta:
    description = "datamaliciousorder - from files 20160517_8951acdd59fc604bc69f8ec0b556af05.js, 20160517_b131b2d453bc820839dd8f826046029f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3898953b8230a6904451bd51e60b3b328f6bcd3969360224d859f36009b1144"
    hash2       = "a32a6b61c45a667d95e44bd5601a1f5396f9ccff0be2e4b12eff89db49f96c6c"

  strings:
    $s1 = "var nConverts1 /* W  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* W  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* W  */;};" fullword ascii
    $s4 = "could = /* W  */(/* W  */\"noitisop\").split(''/* W  */).reverse(/* W  */).join('');" fullword ascii
    $s5 = "enjoy1 /* W  */ /* W  */= true;/* W  */" fullword ascii
    $s6 = "var enjoy1 /* W  */ = false;" fullword ascii
    $s7 = "batch =/* W  */ \"R\" + \"esponseB\"/* W  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}