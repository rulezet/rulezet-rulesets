rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe112068117cc9b20b84261af26f8a4a4636b8320815621f418eedc55e7671e3"

  strings:
    $s1 = "Enterate" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}