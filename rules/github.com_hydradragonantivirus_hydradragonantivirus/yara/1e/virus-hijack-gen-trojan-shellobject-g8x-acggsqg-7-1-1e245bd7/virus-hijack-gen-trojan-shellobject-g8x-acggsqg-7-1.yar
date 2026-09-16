rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCggSqg_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCggSqg_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2abefae0885c7119e0e03d626fe3be3ff4ed3513e0518ad61d2d6c8124df694b"

  strings:
    $s1 = "Continency" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}