rule Trojan_Danger_Trojan_GenericKD_72304918_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63f93fa79593ef8ca1cc6d6a37fe467c3a9985cc6857c9ce78f1bc623c7a8e64"

  strings:
    $s1 = "ODBC Data Sources (32-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}