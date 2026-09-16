rule Virus_Hijack_Trojan_GenericKDZ_98113_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83b949a125dffb2571750ab603ced9bd3c904bb5b5eccac19f028376f7573032"

  strings:
    $s1 = "[]thiR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}