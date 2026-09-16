rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f68ba10c83813c953b976e9624688fba8be092469155508bd4d256787b42dfa7"

  strings:
    $s1 = "frantically" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}