rule Virus_Hijack_Trojan_GenericKDZ_99416_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6516e4df62266528d546c51b3fce6317fea59dc13800ba4d5a07b7db4223d71"

  strings:
    $s1 = "sUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}