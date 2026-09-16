rule Virus_Hijack_Trojan_GenericKDZ_98113_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f71b75193e490c3e8fa6ac53c6dc7aced5b962e2c64bf5cb589b44f75e985801"

  strings:
    $s1 = ">]flEE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}