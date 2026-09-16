rule Trojan_Danger_Trojan_GenericKD_72853156_33 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55ea32edc3cdeba566ea06891c538f2ab731bbce2a6a62a8f3bdb761c73fed7d"

  strings:
    $s1 = "gabi>;^Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}