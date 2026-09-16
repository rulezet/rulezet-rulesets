rule Virus_Hijack_Trojan_GenericKDZ_98113_38_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_38_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74342f8c9758463fb951b0194513f9bf4ecc87a92936a223d13ac385318b0fae"

  strings:
    $s1 = "e!DauW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}