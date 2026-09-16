rule Virus_Hijack_Trojan_GenericKDZ_74550_120_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_120_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59f54550f7a3e2ce3a8ad2761c82d95461afa789cde4a8ce450633edc3a320ff"

  strings:
    $s1 = "A<AroW" fullword ascii
    $s2 = "Jato[l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}