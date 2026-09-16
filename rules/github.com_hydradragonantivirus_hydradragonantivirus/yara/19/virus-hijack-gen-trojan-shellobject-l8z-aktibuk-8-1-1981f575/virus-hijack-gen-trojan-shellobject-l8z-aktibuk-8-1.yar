rule Virus_Hijack_Gen_Trojan_ShellObject_l8Z_aKTibuk_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8472ecbe75e948c0de27593435a7c56fa0a06ce7616c98344be9cd13ef1939a"

  strings:
    $s1 = "Virtual@L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}