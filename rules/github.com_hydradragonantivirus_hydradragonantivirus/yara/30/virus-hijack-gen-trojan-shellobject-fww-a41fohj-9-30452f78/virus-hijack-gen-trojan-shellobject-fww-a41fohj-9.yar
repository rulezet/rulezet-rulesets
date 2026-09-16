rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec174c6af630d433c500be6cc09bcf4b97e5ad65b09ba3af415d94a179e18e7"

  strings:
    $s1 = "Qb(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "Qb(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}