rule Virus_Hijack_Trojan_GenericKDZ_105924_446_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_446_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac6db78b798d368bc198d5b26c5048cd1f0a9e7439fa11ef2beaf2cda73c19a8"

  strings:
    $s1 = "pR)SAip%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}