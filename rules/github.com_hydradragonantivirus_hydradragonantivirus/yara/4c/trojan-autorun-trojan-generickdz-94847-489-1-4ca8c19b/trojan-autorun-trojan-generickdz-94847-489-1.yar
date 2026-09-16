rule Trojan_Autorun_Trojan_GenericKDZ_94847_489_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_489_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "624da9a22d5bc9f61531e6a18f19ec2dcf6a3bb5d4beb6cee2faf4223c4ffebb"

  strings:
    $s1 = "pOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}