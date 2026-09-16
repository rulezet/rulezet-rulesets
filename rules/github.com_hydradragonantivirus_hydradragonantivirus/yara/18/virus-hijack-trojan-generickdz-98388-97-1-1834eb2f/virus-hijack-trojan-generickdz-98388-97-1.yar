rule Virus_Hijack_Trojan_GenericKDZ_98388_97_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_97_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd4db2ed632cb73d77ff1bf7250305b9780533521f2225215040cc9659fa5754"

  strings:
    $s1 = "didYM E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}