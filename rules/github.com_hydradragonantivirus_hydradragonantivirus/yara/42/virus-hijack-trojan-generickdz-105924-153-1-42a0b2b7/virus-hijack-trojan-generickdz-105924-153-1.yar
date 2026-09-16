rule Virus_Hijack_Trojan_GenericKDZ_105924_153_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93ba3ad200b249d0187f33fed658b39cec9d86b62291a98a04b66badb182f39b"

  strings:
    $s1 = "dynamic method does not support fault clause" fullword wide
    $s2 = "Laragon - fast & powerful local development environment     " fullword wide
    $s3 = "StopBlock" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}