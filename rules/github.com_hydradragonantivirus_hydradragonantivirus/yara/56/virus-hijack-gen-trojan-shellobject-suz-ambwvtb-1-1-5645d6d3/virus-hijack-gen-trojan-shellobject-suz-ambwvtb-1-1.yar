rule Virus_Hijack_Gen_Trojan_ShellObject_suZ_amBwvTb_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.suZ@amBwvTb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdf7a9bf9143d36ee7eb3277faa4f84cb4865b38350069d299e14edc60cfce48"

  strings:
    $s1 = "Copyrig}t (c) 1998 Hewlett-Packard Company" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}