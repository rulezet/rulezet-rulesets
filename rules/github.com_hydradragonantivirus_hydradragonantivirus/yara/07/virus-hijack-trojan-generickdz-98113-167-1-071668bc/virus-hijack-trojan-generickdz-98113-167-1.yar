rule Virus_Hijack_Trojan_GenericKDZ_98113_167_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_167_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b433d3a3a87192fb3c3f32089e3753b47032ddfeb1d22736a6c4e1023b3296b9"

  strings:
    $s1 = "u?SCOw" fullword ascii
    $s2 = "wYde{o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}