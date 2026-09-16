rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f53b98b7baf31c1cbadceade171010d4eb333e248e45d1bf5d07974f2c4d0dd6"

  strings:
    $s1 = "Tutorially" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}