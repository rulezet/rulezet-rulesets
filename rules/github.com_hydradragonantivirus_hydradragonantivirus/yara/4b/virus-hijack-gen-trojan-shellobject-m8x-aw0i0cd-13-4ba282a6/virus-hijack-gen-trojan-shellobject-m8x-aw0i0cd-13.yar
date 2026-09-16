rule Virus_Hijack_Gen_Trojan_ShellObject_m8X_aW0I0Cd_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8X@aW0I0Cd_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c129dc4189123802c09919d3636e831ab18c6aec4fd54570cf7cc55d86a07a7"

  strings:
    $s1 = "WoRk)>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}