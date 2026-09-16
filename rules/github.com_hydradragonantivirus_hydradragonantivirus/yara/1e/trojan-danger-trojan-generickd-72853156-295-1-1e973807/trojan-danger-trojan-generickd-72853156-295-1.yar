rule Trojan_Danger_Trojan_GenericKD_72853156_295_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_295_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50143679915dd9a3e72d1f2904f1f50119fdc55250bd176f08972c7019d40a4a"

  strings:
    $s1 = "availability of ExtenSysqemofnueSysqemelkmtSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s2 = "availability of ExtenSysqemofnueSysqemelkmtSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}