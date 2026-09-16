rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59e653cd356480500f42f4b2a8fc4ff45b75e230fec6e1a55f024001eb159d7c"

  strings:
    $s1 = "opurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}