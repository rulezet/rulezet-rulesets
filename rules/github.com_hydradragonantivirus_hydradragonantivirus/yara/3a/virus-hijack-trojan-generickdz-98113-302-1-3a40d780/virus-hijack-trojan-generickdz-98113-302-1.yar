rule Virus_Hijack_Trojan_GenericKDZ_98113_302_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_302_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6dfac8d7f1a9105364d7894be5fcd1a45b70b8f88462abcc060c73feaf7fa6e"

  strings:
    $s1 = "OIMe]:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}