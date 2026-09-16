rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da76cead1bd1169d2b8d00573469dc4125232df6f2be141f2c4083d348d1f09c"

  strings:
    $s1 = "0Ppurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}