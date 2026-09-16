rule Virus_Sysbot_Trojan_GenericKD_71671752_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92ae1d5e69654caf15167da188bbb9c82a5a29fabb13260d87551065a5711be3"

  strings:
    $s1 = "z5(guGU}[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}