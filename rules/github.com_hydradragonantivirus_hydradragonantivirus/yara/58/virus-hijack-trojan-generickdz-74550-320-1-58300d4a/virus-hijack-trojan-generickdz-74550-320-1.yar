rule Virus_Hijack_Trojan_GenericKDZ_74550_320_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_320_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d2101532c29eaa70d6dd50dd3206031ee44ad7a6cc931c1b9194e27976b7c77"

  strings:
    $s1 = "guSH, " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}