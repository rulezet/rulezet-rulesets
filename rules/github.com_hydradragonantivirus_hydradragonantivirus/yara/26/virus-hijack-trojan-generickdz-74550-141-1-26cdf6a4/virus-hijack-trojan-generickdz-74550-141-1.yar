rule Virus_Hijack_Trojan_GenericKDZ_74550_141_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_141_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a996e544e4145ead46724f31180225b8f1b6cb9f8286bec97bb3acc081f5a6d8"

  strings:
    $s1 = "zeRo{s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}