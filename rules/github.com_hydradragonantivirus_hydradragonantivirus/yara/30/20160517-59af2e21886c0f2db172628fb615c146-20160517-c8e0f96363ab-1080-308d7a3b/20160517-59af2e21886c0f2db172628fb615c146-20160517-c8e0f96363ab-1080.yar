rule _20160517_59af2e21886c0f2db172628fb615c146_20160517_c8e0f96363ab_1080 {
  meta:
    description = "datamaliciousorder - from files 20160517_59af2e21886c0f2db172628fb615c146.js, 20160517_c8e0f96363ab644cb830f50ece3fff4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20efe9886176946634890cbc8658fe3f57dcc067f0b41b5021956b3880018a74"
    hash2       = "9e38431fd5da4a242eef39e26be4d641214d06eec610c35f53962a4f3bf540ce"

  strings:
    $s1 = "var nConverts1 /* D  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* D  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* D  */;};" fullword ascii
    $s4 = "var enjoy1 /* D  */ = false;" fullword ascii
    $s5 = "could = /* D  */(/* D  */\"noitisop\").split(''/* D  */).reverse(/* D  */).join('');" fullword ascii
    $s6 = "enjoy1 /* D  */ /* D  */= true;/* D  */" fullword ascii
    $s7 = "batch =/* D  */ \"R\" + \"esponseB\"/* D  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}