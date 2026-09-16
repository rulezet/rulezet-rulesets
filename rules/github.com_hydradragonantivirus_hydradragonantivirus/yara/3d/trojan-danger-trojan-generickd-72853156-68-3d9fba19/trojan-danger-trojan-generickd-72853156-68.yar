rule Trojan_Danger_Trojan_GenericKD_72853156_68 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_68.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e5432339ffc08efd4646143fd96e6cd230d2a005dce79b704eabafb65d5c122"

  strings:
    $s1 = "Check For Updates.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}