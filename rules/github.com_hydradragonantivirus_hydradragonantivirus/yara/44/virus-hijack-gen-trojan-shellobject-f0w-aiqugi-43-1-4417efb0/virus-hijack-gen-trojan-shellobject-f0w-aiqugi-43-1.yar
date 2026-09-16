rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_43_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2875f24fbd6d6e1daba9901fda31eb0a417c2fa0211d14b84b9e6b58a26c706"

  strings:
    $s1 = "pVirtual Device List" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}