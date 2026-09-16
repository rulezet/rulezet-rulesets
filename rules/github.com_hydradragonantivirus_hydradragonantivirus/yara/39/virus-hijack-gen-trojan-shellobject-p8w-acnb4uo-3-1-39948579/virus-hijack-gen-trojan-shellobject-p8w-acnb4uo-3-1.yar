rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_aCNb4Uo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd183bd92503f98c8e039f85345d75e133f295a3358f6b72e776e7806a7971db"

  strings:
    $s1 = "attA}6c" fullword ascii
    $s2 = "CORE;5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}