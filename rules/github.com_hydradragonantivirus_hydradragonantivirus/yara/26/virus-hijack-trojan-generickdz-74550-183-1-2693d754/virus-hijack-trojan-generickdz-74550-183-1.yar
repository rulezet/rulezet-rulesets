rule Virus_Hijack_Trojan_GenericKDZ_74550_183_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_183_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75d28d4878b4f2ebd1b1e06b2f09cc246ef4397b51292fc909b3a6a98a39dc47"

  strings:
    $s1 = "P}U)SPEW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}