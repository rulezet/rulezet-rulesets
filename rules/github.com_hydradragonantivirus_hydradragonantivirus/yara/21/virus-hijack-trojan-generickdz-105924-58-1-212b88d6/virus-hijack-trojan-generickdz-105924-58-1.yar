rule Virus_Hijack_Trojan_GenericKDZ_105924_58_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_58_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81fcaa22d98d8ba906f1c05984f309fd063fde2a6eab56f7606ea87600c0e7ab"

  strings:
    $s1 = "T<miaN" fullword ascii
    $s2 = "9)pOck" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}