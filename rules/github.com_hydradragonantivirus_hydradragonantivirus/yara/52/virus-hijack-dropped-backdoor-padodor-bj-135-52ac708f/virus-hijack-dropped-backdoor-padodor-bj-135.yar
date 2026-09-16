rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_135 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_135.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24c95f7d5a6918735402e047f20d71fa23b257c572cd5dc421e3080b2e788a26"

  strings:
    $s1 = "EIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}