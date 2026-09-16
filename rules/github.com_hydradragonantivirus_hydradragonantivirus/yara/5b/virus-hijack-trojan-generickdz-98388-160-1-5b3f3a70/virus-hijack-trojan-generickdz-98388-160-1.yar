rule Virus_Hijack_Trojan_GenericKDZ_98388_160_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_160_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6257e39a78e3e1c97db77d5095d4c8db28ecff5d9800767b01488fc836e7cb3"

  strings:
    $s1 = ".:euge!" fullword ascii
    $s2 = "tahA `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}