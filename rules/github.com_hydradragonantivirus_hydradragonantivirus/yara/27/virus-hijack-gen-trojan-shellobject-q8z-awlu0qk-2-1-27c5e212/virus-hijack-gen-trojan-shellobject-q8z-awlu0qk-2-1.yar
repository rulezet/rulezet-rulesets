rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15147f7efe0aeb484145b9253ff182aed13200e27bbb9cf1e7e933a614de3fb5"

  strings:
    $s1 = "bIas]*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}