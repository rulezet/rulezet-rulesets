rule Virus_Infector_Trojan_GenericKDZ_96072_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKDZ.96072_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd1a10c50bb64f5f50916c17b68ffcd6198d851c0030485ea3533afa6f1355c4"

  strings:
    $s1 = ",Reference Viewing Condition in IE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}