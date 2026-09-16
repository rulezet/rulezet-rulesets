rule Virus_Sysbot_Trojan_GenericKD_73132233_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.73132233_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f19a14b0380a84de54741be18c87ea7b1f065a9020001b265324fc73fef97d50"

  strings:
    $s1 = "*<YEAN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}