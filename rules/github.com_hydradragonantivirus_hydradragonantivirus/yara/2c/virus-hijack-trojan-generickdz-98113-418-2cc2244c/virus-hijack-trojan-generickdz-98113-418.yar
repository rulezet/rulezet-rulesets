rule Virus_Hijack_Trojan_GenericKDZ_98113_418 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_418.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "529011e84c0212bb99ad4c51f892f367de8b099ecf6124facfc70d3c14bd1f26"

  strings:
    $s1 = "Sor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}