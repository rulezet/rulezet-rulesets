rule Trojan_Danger_Trojan_GenericKD_72677122_185_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0985a53049af01cba19a824414212c7cb2864e8fcf2b388c0680a5383d678011"

  strings:
    $s1 = "GolfUpdate, Version 1.0" fullword wide
    $s2 = "About GolfUpdate" fullword wide
    $s3 = "pl]Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}