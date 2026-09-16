rule Trojan_Danger_Trojan_GenericKD_72853156_414 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_414.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4939e7261727fa3f2e813bb6de5d30118cf31f99898f60b0b96c8bc8a3456d9d"

  strings:
    $s1 = "Python (command line).lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}