rule Virus_Hijack_Gen_Trojan_ShellObject_B8Z_ayQY28h_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.B8Z@ayQY28h_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57ab05f7a9429e7dcc7297150281f4c1dae7c0796cbd68d129d8189201e9a43e"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}