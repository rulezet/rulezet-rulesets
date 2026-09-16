rule Virus_Hijack_Trojan_GenericKDZ_74550_239_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_239_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a76cca80eb146d475dddcd9f4c0e25bd11e138aa288f2ce7527296ae76cdfefe"

  strings:
    $s1 = "dolT*9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}