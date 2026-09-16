rule Virus_Hijack_Trojan_GenericKDZ_74550_292_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_292_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a34d264b9673c8f972998ef19888d5db9272de10517753bcfc69a7963f8d286b"

  strings:
    $s1 = "WACkE):o'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}