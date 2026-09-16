rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_22_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_22_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23430e8f7918839a6f8c09805d392f816cafd7678523b736d5e8db386318e68"

  strings:
    $s1 = "Program Files (x86).exe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}