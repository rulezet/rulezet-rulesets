rule Virus_Hijack_Trojan_GenericKDZ_103285_384 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_384.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd2cb1f1c72877d9e8551c479ca047a3ad9a9bfb0d36ea5bfd211974ebf15e72"

  strings:
    $s1 = "user minimum table in the licensing rules section" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}