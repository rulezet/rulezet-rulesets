rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "886f176e93a57a1782d2ecb519c10cfd1290325d55748a99ad742190a59f3106"

  strings:
    $s1 = "Undertimed" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}