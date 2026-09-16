rule Virus_Hijack_Trojan_GenericKDZ_103285_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92775d72a54ad37b11043a7a88918328e1388ce249f01e611ea13f20a2171dcd"

  strings:
    $s1 = "LnComputer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}