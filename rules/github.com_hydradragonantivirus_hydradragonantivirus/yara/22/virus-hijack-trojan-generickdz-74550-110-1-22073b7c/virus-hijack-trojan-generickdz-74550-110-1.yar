rule Virus_Hijack_Trojan_GenericKDZ_74550_110_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_110_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18588d23ceef48c5716495a52ca9bca01c1a1b8981469dfe303d7cd9be12b054"

  strings:
    $s1 = "GoBi [" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}