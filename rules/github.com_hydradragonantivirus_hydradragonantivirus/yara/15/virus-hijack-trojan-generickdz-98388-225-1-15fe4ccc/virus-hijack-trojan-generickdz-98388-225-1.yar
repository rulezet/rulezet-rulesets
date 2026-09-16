rule Virus_Hijack_Trojan_GenericKDZ_98388_225_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_225_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c874042b1d10d81ea282deaa5e3d7afb5f2d9e5c0e4f88936ae2cf4b06ae1478"

  strings:
    $s1 = "{niATa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}