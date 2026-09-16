rule Virus_Sysbot_Trojan_GenericKD_61340032_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.61340032_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcc89112b90ab060278a59df04cbd9d283b38d634fa91a549570b08eed18fb6a"

  strings:
    $s1 = "!Th D program cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}