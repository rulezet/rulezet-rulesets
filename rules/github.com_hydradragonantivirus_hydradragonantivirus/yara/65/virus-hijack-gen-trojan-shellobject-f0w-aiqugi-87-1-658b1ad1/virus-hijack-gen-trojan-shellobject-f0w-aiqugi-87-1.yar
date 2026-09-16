rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_87_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2af56e126327f5c7315dd088cfd055488f5ae764187f54cc24e7149b335b6fc9"

  strings:
    $s1 = "***; for 16-bit app support" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}