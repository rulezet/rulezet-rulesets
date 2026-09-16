rule Trojan_Sysbot_Trojan_GenericKDZ_104643_28 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49f924850b1780fa4d49100f5de48e65da4c4af69d894a6102a110f19d401337"

  strings:
    $s1 = "gram F" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}