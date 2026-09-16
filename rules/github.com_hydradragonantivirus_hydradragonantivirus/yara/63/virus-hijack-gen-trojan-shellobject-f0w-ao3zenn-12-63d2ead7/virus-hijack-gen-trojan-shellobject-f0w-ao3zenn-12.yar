rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccf9086f6445adc2187e1f4798180ed6637d7dbc502fd54093c4b59659a27f1d"

  strings:
    $s1 = "~Cdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}