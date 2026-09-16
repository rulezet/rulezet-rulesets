rule Trojan_Danger_Trojan_GenericKD_72853156_52_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_52_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a20a86f128ccd899930ae15fd08fdddb40e0ba4b114216e8048e59524de6b2a"

  strings:
    $s1 = "ith SOAP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}