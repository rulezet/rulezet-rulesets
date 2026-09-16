rule Virus_Hijack_Trojan_GenericKDZ_74550_168_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_168_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e69537681a6d8ed4fdedd6a548955640e58cb964de0b77d4aae0fcdbad289ef"

  strings:
    $s1 = "r%DUIT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}