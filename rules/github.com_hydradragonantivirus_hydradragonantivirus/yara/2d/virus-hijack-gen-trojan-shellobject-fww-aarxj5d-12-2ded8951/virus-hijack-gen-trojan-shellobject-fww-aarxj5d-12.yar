rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fe3c375b97171f153620ba6d7428762e4a309c7019702828caae7439f3ceb9a"

  strings:
    $s1 = "gpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}