rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_260_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_260_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f1596b4ebd177ec46e57ea0e6d208f32c1ebb93b448a4b5318cc116293d1e71"

  strings:
    $s1 = "SneB@L" fullword ascii
    $s2 = "h%rEaL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}