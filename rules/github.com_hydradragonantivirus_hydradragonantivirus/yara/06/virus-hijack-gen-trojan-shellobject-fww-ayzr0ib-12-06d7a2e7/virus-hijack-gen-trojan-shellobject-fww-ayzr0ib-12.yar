rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06ebbd1dfe1cc2ddf4c89bf257e17a56965338e93c3456bb1222abd0a3e65c7c"

  strings:
    $s1 = "O1purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}