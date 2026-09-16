rule Virus_Hijack_Trojan_GenericKDZ_105924_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b991a9b6a517c3494ef8de15f42bfdfa21da1923af5021899b105d5ff723809d"

  strings:
    $s1 = "cd$hAJe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}