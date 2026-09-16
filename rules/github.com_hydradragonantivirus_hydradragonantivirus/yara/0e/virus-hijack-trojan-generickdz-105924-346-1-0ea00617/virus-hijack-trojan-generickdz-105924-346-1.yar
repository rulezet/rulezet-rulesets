rule Virus_Hijack_Trojan_GenericKDZ_105924_346_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_346_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82564cdb58cf61a6cc02dd59879a94522629999d36461277e46156d062506d09"

  strings:
    $s1 = "GLIa{a" fullword ascii
    $s2 = ";kapA%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}