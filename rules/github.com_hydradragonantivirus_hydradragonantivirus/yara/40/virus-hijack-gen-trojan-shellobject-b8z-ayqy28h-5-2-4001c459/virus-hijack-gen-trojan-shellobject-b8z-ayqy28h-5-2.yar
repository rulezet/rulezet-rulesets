rule Virus_Hijack_Gen_Trojan_ShellObject_B8Z_ayQY28h_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.B8Z@ayQY28h_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48e14f49a4a52692f7b3441e587bc1586234d4978cdc298b4ce92eb706653d34"

  strings:
    $s1 = "rOKa;[&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}