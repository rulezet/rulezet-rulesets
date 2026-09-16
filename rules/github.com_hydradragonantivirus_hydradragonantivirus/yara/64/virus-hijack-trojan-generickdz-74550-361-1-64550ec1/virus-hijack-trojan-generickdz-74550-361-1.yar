rule Virus_Hijack_Trojan_GenericKDZ_74550_361_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_361_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3cf762e69fbce31a0b7a3a0df140bedf782418b868693c2645b4e911d728072"

  strings:
    $s1 = "KirN%T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}