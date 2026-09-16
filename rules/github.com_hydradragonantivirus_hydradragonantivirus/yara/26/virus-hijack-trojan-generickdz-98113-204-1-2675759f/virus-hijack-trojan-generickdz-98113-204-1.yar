rule Virus_Hijack_Trojan_GenericKDZ_98113_204_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_204_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f555f24e62a6e6a2e5d001664ccb6b5d74256be1e3850463f772ebdd5755524d"

  strings:
    $s1 = "MeWl}]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}