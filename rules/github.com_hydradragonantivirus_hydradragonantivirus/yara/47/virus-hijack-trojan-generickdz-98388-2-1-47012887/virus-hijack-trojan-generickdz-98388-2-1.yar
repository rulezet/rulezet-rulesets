rule Virus_Hijack_Trojan_GenericKDZ_98388_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e18c65ee9690cc43e68c4abb3d88f1cf0d02659a39592a37951444dd1e8b602"

  strings:
    $s1 = "{fUme}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}