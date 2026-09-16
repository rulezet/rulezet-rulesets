rule Virus_Hijack_Trojan_GenericKDZ_74550_354_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_354_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9913fb7f9d6e3015b9d0893a8acdab17c772b5ae14afbe6371c13b1e42c56b41"

  strings:
    $s1 = "!g;wHAU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}