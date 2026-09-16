rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae73ef74543ce177e7d376df37c9d497df69bdb3777a5e3efa5cc43205321414"

  strings:
    $s1 = " 2012 - 2019. Razer Inc." fullword wide
    $s2 = "FlatSplitter_Demo Version 1.0" fullword wide
    $s3 = "Razer Cortex" fullword wide
    $s4 = "About FlatSplitter_Demo" fullword wide
    $s5 = "FlatSp Document" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}