rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "116285555acdb0758adab8b4a36551fed423f3292bd0b8d09c852696c4db2cb1"

  strings:
    $s1 = "wEEd!Za'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}