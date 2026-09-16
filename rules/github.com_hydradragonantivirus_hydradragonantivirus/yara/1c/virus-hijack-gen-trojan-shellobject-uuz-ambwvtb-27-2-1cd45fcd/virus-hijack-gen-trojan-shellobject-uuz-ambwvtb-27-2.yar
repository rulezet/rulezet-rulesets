rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_27_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_27_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcf671767d01a5e993e720dc890ab2735322bbafaac947f3e7e1a427476c445c"

  strings:
    $s1 = "Flicks Training" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}