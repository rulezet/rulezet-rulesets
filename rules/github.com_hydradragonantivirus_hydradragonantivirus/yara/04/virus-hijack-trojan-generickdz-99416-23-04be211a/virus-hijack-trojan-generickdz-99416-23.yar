rule Virus_Hijack_Trojan_GenericKDZ_99416_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "564d570c534e4e7fb8ca55fe7ec05372de6dd18f8f4c6e6c7b552f3e78def235"

  strings:
    $s1 = "cUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}