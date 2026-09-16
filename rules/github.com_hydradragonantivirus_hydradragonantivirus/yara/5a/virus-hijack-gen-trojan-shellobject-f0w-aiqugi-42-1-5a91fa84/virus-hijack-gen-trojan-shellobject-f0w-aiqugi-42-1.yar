rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_42_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76f724ef5ae9acd55c065ef895121b1bb7d27b0a54261475c138cca747afc1de"

  strings:
    $s1 = "11.0.61135.400 built by: RTMLDR" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}