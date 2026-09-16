rule Trojan_Danger_Trojan_GenericKD_72853156_140 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_140.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e40e83e8a9b65a95f3b3463ad44422bcc06b2fdc83c7b1c82ced9e1acb5b2913"

  strings:
    $s1 = "upgrade " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}