rule Virus_Hijack_Trojan_GenericKDZ_74550_38_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_38_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50d7ca16371947d1ea9c9e478dc5b48babb8d4579f3a64997e3571436b065609"

  strings:
    $s1 = "Q,oBOe" fullword ascii
    $s2 = "jESs,:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}