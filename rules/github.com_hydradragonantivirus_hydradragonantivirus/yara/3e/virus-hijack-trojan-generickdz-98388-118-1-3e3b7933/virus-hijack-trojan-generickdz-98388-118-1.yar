rule Virus_Hijack_Trojan_GenericKDZ_98388_118_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_118_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a37fef34b52a61b76034865ced1d5c6f1e3b559fd410f2806ef296b2a8169fa8"

  strings:
    $s1 = "1 dRUB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}