rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aSlVvue_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4911b5f8f80c7a66f5abbdf516ed1ca2706c7b980c8e3cb36fb2ea1193c796a"

  strings:
    $s1 = "ISTask for Inno Setup" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}