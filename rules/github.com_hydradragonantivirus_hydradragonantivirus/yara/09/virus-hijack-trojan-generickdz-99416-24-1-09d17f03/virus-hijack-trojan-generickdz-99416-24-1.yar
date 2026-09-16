rule Virus_Hijack_Trojan_GenericKDZ_99416_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a040892384316f491466e698502dbed8446c40429301e983afbebcc27e7fcebf"

  strings:
    $s1 = "sodY%P!t" fullword ascii
    $s2 = "m:teFF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}