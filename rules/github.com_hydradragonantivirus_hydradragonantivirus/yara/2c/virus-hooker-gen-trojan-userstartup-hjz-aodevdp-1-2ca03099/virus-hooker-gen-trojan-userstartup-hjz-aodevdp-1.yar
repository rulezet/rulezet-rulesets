rule Virus_Hooker_Gen_Trojan_UserStartup_hjZ_aODEVdp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Trojan.UserStartup.hjZ@aODEVdp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5357eea39d555157ccf9cf18f272471a48ae2f84f636600e0ff3d09488c1c92"

  strings:
    $s1 = "sOph>G" fullword ascii
    $s2 = "%)huSS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}