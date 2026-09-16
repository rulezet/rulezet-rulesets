rule _20160517_0c9135eb6b19f0f84b8bd382bfc49bb2_20160517_a3672c19a2b9_1062 {
  meta:
    description = "datamaliciousorder - from files 20160517_0c9135eb6b19f0f84b8bd382bfc49bb2.js, 20160517_a3672c19a2b9168ff09f34328f3a330c.js, 20160517_fc056421626a1deca6a9d516c9569428.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cda3826c4d1b2569846e4a1aed36da018ef07d2fc8e7d7e5f44d055ac6150960"
    hash2       = "99c17064a4640e247e7d35e51138a41a9ac36b0b9c36af44217877a64feb9e02"
    hash3       = "0b7dd055abedb4e00ee52e61d855fa71e9a98dd4ed64550b9c77227247103c79"

  strings:
    $s1 = "var nConverts1 /* g  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* g  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* g  */;};" fullword ascii
    $s4 = "enjoy1 /* g  */ /* g  */= true;/* g  */" fullword ascii
    $s5 = "var enjoy1 /* g  */ = false;" fullword ascii
    $s6 = "could = /* g  */(/* g  */\"noitisop\").split(''/* g  */).reverse(/* g  */).join('');" fullword ascii
    $s7 = "batch =/* g  */ \"R\" + \"esponseB\"/* g  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}