rule Virus_Hijack_Trojan_GenericKDZ_99416_47 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_47.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0a53b8f87a3b694bdb84b48599378d513b7a36ff120d74dbcdb662e51d81915"

  strings:
    $s1 = "XUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}