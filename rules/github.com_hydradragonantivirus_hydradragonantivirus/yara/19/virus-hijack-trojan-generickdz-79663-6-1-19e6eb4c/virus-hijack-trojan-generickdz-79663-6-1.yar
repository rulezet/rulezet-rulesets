rule Virus_Hijack_Trojan_GenericKDZ_79663_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d964990f5cf807e281071ba85171ac8cd14965fcd05d803be884d3525b98704"

  strings:
    $s1 = "q*tRAm" fullword ascii
    $s2 = "V$JOcH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}