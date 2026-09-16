rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79241d1d84e8b48162b76efa403fb9628068baad3fd23a3ba4a6b8e73cf1f4ec"

  strings:
    $s1 = "iFn_mh#X\\:rOxY#B." fullword ascii
    $s2 = "aFaR&EoEeJc" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}