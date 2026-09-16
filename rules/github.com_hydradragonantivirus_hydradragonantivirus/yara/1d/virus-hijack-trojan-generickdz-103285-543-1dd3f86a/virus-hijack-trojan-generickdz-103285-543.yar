rule Virus_Hijack_Trojan_GenericKDZ_103285_543 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_543.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1595d2b1595a9750db4daf0485b5d7bc2c2d84abdc0273248048f0e087533d60"

  strings:
    $s1 = "~Fpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}