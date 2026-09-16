rule Virus_Hijack_Trojan_GenericKDZ_74550_202_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_202_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d4e7f2a1fcd7b017a38230c7553225d0ba776555c68a7b74ad78ce103660f8c"

  strings:
    $s1 = "BoGy:>9" fullword ascii
    $s2 = "LYAm`V" fullword ascii
    $s3 = "B&rUga" fullword ascii
    $s4 = "lHF!yeDE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}