rule Virus_Hijack_Trojan_GenericKDZ_105924_522_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_522_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f062db662df15ab394a4e89c156209aaa443c3075ec717da9f6feee3f5df844"

  strings:
    $s1 = "\"bC9[KUNG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}