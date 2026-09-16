rule Virus_Hijack_Trojan_GenericKDZ_98113_86_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0476053611bd0a77bb6629a7a71462b6193ad2288cc1a043adf8606b59123d97"

  strings:
    $s1 = "rc,MeAd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}