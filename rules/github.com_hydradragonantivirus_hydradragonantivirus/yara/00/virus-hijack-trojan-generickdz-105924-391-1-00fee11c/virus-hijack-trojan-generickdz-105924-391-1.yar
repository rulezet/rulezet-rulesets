rule Virus_Hijack_Trojan_GenericKDZ_105924_391_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_391_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "283731df4e41b38178c6f7f10155e1859f2b96a195bc7c08cdc5630cf5f68542"

  strings:
    $s1 = "maIN.@ph&" fullword ascii
    $s2 = "< yIRN" fullword ascii
    $s3 = "tEFF(u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}