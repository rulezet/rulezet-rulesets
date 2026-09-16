rule Virus_Hijack_Trojan_GenericKDZ_98113_118_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_118_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00f974e61de5102b624885989b28955a7f4c3b89e66e3326266498443478af32"

  strings:
    $s1 = "lEaF<B|" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}