rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dbe91878da0670bd9c67982ad211d962c8485b7b01f094bec2803709eb66ecf"

  strings:
    $s1 = "8~purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}