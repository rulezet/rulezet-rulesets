rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aO_sVhl_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aO@sVhl_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45a607ab8a447a0950500573f32bd5a2377699e650d65931ffa812ea6eb302f9"

  strings:
    $s1 = "Office Telemetry Agent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}