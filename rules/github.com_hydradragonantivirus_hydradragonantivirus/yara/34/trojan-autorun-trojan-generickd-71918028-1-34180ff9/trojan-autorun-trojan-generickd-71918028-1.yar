rule Trojan_Autorun_Trojan_GenericKD_71918028_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.71918028_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f0d6c5899af10eaecab8e6afe0da86e0f8b34b1e50ec17759299f758995c8ea"

  strings:
    $s1 = "vby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}