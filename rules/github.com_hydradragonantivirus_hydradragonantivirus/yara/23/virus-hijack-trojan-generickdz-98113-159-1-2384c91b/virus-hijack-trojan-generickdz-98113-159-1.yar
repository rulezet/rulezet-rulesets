rule Virus_Hijack_Trojan_GenericKDZ_98113_159_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_159_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bebf41babd98743a0e1660ad37c8da67bd8bb1c5fe33150a7c553ef586813d5"

  strings:
    $s1 = "z\"GurR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}