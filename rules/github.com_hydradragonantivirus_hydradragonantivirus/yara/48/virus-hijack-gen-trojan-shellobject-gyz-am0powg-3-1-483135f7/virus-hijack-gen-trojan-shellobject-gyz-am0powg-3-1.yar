rule Virus_Hijack_Gen_Trojan_ShellObject_GyZ_am0pOwg_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GyZ@am0pOwg_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfe0c8f95bf96e2be4666d73ef9cd166e89eef631e975aa2e384d9f1af901d45"

  strings:
    $s1 = "lete Obj" fullword ascii
    $s2 = "li} has made a.tC" fullword ascii
    $s3 = ". ??e{flat}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}