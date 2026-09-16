rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_45 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_45.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ccfc4ea8af1e76780a41572918a397798def956e4fe2ca5d82cb62b9a150055"

  strings:
    $s1 = "A%U#StOG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}