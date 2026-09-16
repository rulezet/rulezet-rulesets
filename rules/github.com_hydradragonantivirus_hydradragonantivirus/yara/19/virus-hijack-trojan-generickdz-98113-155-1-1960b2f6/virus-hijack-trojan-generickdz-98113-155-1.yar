rule Virus_Hijack_Trojan_GenericKDZ_98113_155_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_155_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21e8e4b1af1adfd1b86e7200e48348024d78eb7765402f88edf949355ea18f34"

  strings:
    $s1 = "FRaB&k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}