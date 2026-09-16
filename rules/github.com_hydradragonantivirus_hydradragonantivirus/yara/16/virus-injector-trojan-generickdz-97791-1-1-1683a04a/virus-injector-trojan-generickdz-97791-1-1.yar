rule Virus_Injector_Trojan_GenericKDZ_97791_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.GenericKDZ.97791_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6296c0347e4c3366a9530d6df6f1aa650d868ac279ce3531b20c338c75baa63b"

  strings:
    $s1 = "+}kemp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}