rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a230b1ac99b46c3c8ed1cf70177dca92a8d04e1b42b55239fbc9594453611e70"

  strings:
    $s1 = "bpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}