rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_108_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_108_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712a9e97a9ac55de87b0bccffc0151ba4c86fb60681d99b2c47d678c6db87333"

  strings:
    $s1 = " Loader" fullword wide
    $s2 = "Copyright ? 2021" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}