rule Virus_Hijack_Trojan_GenericKDZ_98113_116_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_116_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57695d7257fcc583234e6d64d01c2e707afa8f746e198ad280a7a5c8fee8d580"

  strings:
    $s1 = "cOTO%," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}