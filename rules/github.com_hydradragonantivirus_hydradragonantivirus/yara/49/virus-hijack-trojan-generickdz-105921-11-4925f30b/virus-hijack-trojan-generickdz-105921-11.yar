rule Virus_Hijack_Trojan_GenericKDZ_105921_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48241c9445f896eb8bb290a917e426a496a1225afe3bbf5c8720999e218ebdac"

  strings:
    $s1 = "qV2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}