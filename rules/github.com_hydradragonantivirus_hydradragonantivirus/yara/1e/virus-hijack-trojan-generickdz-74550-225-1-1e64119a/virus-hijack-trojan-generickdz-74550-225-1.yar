rule Virus_Hijack_Trojan_GenericKDZ_74550_225_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_225_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "958ead77da5565a02aaf2a9cef557da5efc7f3c41f60948cd7475de633e34f16"

  strings:
    $s1 = "@n[HaKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}