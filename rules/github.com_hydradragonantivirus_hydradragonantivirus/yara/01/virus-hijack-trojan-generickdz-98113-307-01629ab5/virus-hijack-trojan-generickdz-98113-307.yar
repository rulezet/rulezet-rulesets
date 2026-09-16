rule Virus_Hijack_Trojan_GenericKDZ_98113_307 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_307.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "970cb8890c55b37eb4b02265013db9b469a88c1bc7c41a6381b7dc533f0c2839"

  strings:
    $s1 = "8&tYPO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}