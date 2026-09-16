rule Virus_Sysbot_Trojan_GenericKD_71671752_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a98caf913169266ca3c29246bec51064490d382a63e1348eff067f435f50b6eb"

  strings:
    $s1 = "X@sAMh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}