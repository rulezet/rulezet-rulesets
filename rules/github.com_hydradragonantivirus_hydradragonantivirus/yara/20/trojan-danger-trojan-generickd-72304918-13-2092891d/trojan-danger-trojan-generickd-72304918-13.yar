rule Trojan_Danger_Trojan_GenericKD_72304918_13 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9461024e4b2b73c0e8d4fc73d857e5acae0a66eb6d003ed079939d49ddf231e7"

  strings:
    $s1 = "ODBC Data Sources (32-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}