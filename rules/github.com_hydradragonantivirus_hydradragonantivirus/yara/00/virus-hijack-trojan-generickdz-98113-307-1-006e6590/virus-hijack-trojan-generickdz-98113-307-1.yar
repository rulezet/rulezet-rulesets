rule Virus_Hijack_Trojan_GenericKDZ_98113_307_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_307_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a3c54d7502428f42b3f75d161d5e1ee41da5e6bf4bfb2f8bfdd7defdc0be55"

  strings:
    $s1 = "0#CopE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}