rule Virus_Hijack_Trojan_GenericKDZ_105924_559_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_559_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1994f4150d6658a170fb6e542d64fbd24e03a2f183feb5d96acc474671060a23"

  strings:
    $s1 = "5*lURk" fullword ascii
    $s2 = "?;X\"}MiTRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}