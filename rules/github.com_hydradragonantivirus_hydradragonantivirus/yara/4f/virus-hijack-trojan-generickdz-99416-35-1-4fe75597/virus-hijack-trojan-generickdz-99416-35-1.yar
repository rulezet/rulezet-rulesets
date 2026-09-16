rule Virus_Hijack_Trojan_GenericKDZ_99416_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "637d73dc34fafde76298926f75e2dd47c8f8c24bcd1742643468564629fee581"

  strings:
    $s1 = "paTa '" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}