rule Virus_Hijack_Trojan_GenericKDZ_98388_61_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa0e9fa10f7918bd2607114c4c8c9398a28bb67c21923735bf1cabf8111ac21a"

  strings:
    $s1 = "W@croy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}