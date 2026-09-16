rule Virus_Hijack_Trojan_GenericKDZ_79663_121_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7463e5df5932a80c63dc25bc6e9ee71ae2baf9e3b5d053456314f0750edc0f43"

  strings:
    $s1 = ">#byON" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}