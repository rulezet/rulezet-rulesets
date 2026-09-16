rule Virus_Hijack_Trojan_GenericKDZ_105924_69_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0583cd7a896d359ccf173f69938f7f8c67a8d8e15fb6ccc87aa7a3a67b5d3e8"

  strings:
    $s1 = "okRA[d_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}