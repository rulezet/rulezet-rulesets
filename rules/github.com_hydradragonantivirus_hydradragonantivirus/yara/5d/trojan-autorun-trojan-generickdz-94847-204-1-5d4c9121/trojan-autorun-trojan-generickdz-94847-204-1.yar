rule Trojan_Autorun_Trojan_GenericKDZ_94847_204_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_204_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02bc3f48bbc40a5d13f77591a3e18e8c8516b7b13748af536edf8b8d08edce82"

  strings:
    $s1 = "xAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}