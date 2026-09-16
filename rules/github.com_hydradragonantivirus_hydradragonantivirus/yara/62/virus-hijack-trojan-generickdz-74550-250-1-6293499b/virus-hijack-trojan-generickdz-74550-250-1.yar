rule Virus_Hijack_Trojan_GenericKDZ_74550_250_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_250_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "add729e198fab4e82af68f5c0b41aa286cfaeb3a8bba94c1c14b02018092eacc"

  strings:
    $s1 = "BaNe$M" fullword ascii
    $s2 = "{HYpo)" fullword ascii
    $s3 = "vBInk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}