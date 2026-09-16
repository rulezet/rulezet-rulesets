rule Trojan_Autorun_Trojan_GenericKD_73204656 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.73204656.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7449317f51e3a74d2df2dab63fa20c3602d5114503b16bf85662b32c3208677"

  strings:
    $s1 = "YVisible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "V::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}