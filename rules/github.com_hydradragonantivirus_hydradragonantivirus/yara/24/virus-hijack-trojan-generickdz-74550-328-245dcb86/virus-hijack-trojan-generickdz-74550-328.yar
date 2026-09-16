rule Virus_Hijack_Trojan_GenericKDZ_74550_328 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_328.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c97e641e5eab1c6ecb579cb4cbaba2d17cc3675d53533d3298d93d2ceb2212f"

  strings:
    $s1 = "onzA;^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}