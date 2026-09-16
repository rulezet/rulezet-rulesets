rule Virus_Hijack_Trojan_GenericKDZ_98388_147_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_147_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecccc86a6fd49869039d314a642e7caa3b1887e5a17ab6d5c7aedba9d4973b5c"

  strings:
    $s1 = "M}wHop`t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}