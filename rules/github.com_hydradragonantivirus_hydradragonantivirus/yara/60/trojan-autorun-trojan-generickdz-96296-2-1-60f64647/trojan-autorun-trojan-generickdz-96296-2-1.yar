rule Trojan_Autorun_Trojan_GenericKDZ_96296_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.96296_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad203f59df5a2a30b619f7f884b86e5d001d9bf90449c5b899a0d289132f04d5"

  strings:
    $s1 = "fPAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii
    $s2 = "Limited, East Point Business Park, Fairview, Dublin 3, Ireland," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}