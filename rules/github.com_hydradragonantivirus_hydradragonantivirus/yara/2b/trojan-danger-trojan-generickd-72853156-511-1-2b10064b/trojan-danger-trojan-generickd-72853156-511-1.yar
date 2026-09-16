rule Trojan_Danger_Trojan_GenericKD_72853156_511_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_511_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9ed7ff91613eee1a6fb69e38a7424b6bf70fa81d6c0c718c420c3f74322527e"

  strings:
    $s1 = "t+ IntegratX with SO(" fullword ascii
    $s2 = "Termin*b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}