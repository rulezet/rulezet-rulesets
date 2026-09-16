rule Trojan_Autorun_Trojan_GenericKD_72517131_244_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_244_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed1446da1b67e8d3ee88d1c5f175be95f47192c5a8f630c806a8f50eaddb2be3"

  strings:
    $s1 = "KDby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}