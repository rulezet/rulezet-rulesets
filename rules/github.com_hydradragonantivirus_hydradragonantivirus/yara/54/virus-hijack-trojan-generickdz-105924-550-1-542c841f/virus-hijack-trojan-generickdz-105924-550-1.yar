rule Virus_Hijack_Trojan_GenericKDZ_105924_550_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_550_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60f9c55997bbee3924f81cc1d6aec7e7711d1baaead33ddfd5255ec55c749965"

  strings:
    $s1 = "]!crIC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}