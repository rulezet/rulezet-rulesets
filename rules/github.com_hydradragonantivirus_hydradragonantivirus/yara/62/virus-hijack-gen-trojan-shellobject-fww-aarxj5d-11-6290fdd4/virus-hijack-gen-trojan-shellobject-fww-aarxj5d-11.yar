rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49c0267a0d6374b3207f5281253ed2e79af189376e685dfa4f7d00e0071f6b2d"

  strings:
    $s1 = "ykpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}