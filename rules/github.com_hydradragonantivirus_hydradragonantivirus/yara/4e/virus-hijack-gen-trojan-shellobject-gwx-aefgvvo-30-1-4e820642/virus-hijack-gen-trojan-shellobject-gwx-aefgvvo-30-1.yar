rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcd87c1830f4dc06702b299f9db9ca5d01f3cf97823a36883f96fdddfa7373c4"

  strings:
    $s1 = "Tidbit" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}