rule Trojan_Sysbot_Trojan_SalityStub_F_24_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.SalityStub.F_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20de06845645ed178865b8c32d1a0f5eda090836cd0a2933ed58d74dd6297df2"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}