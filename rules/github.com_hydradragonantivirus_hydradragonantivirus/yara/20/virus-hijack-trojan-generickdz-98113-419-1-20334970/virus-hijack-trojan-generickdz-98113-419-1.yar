rule Virus_Hijack_Trojan_GenericKDZ_98113_419_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_419_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6da22713ae58ac99e9b5b633dedb9ccdee8c22f250a5ea2f5b45ba7a5ea9a07b"

  strings:
    $s1 = "M}HUKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}