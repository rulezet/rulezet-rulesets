rule Trojan_Danger_Trojan_GenericKD_72250432 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72250432.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b2cc33ca884d82e7bed3e120003342be4ef7de63dddd5269bea37a5b9529913"

  strings:
    $s1 = "REFUSE" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}