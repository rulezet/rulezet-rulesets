rule Virus_Hijack_Trojan_GenericKDZ_74550_190_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_190_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b8c633afe8bdb78c1dc6fb0caecec7ff0ccaa4257f50891b534305a9172d0aa"

  strings:
    $s1 = ")`EArl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}