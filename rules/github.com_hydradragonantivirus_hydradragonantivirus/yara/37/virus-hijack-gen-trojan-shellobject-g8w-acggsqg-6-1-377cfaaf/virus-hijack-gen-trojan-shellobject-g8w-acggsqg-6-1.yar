rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCggSqg_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCggSqg_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df827da11dc6e6ee35f616e19c10f01aeae8294b7826601abddaec240cbda8d8"

  strings:
    $s1 = "?]wOlD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}