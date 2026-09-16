rule Virus_Hijack_Trojan_GenericKDZ_105924_543_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_543_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52e6c6f30a952265b5adc200faa0ae6cce2dd0ad0664e5f1ec8d183b6708b806"

  strings:
    $s1 = "DIce@=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}