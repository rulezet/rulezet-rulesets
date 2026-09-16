rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b7b10aab2e37907873104583dbab5f1ea96ac29066d3db4205e0044d19055e"

  strings:
    $s1 = "Herbivore" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}