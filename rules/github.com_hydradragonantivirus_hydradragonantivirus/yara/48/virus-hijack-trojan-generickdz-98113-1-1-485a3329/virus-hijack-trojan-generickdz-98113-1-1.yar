rule Virus_Hijack_Trojan_GenericKDZ_98113_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34c0b63bb1b236b58653d5810f14fb739de0e42233ece0f873d57b38fdc43148"

  strings:
    $s1 = ",BRAd," fullword ascii
    $s2 = "#AlLy$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}