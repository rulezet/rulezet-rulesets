rule Virus_Hijack_Trojan_GenericKDZ_98388_104_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_104_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19ad275a5bd1e1696cd1280897c140bde162c18260ae5a19e1720aac08e76393"

  strings:
    $s1 = "SNed%4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}