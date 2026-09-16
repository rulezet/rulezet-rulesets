rule Trojan_Autorun_Trojan_GenericKD_72517131_167_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_167_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ac08e55eee4e9b8db108741c0cf0137765eacd1f0463a9671ace52c554d645"

  strings:
    $s1 = "+User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}