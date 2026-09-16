rule Virus_Hijack_Trojan_GenericKDZ_99416_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5c2ac89fbd82502b8c5b738e3b9ba2279bc0ed9dcbcfd43ae1018348bcfd7c2"

  strings:
    $s1 = ";raVE%\"B" fullword ascii
    $s2 = "hIZz)F." fullword ascii
    $s3 = "tuan:yj" fullword ascii
    $s4 = "uRdE#Ra" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}