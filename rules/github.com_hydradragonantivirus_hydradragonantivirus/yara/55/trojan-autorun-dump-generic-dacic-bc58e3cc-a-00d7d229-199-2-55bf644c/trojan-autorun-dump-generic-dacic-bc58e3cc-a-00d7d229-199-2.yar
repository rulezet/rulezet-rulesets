rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_199_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_199_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad9c9a0c469fd85e76b5b1aa9f53be3f5162303df9170823be8549404ea64831"

  strings:
    $s1 = "RE stapler cistodc1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}