rule Trojan_Danger_Trojan_GenericKD_72304918_115_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_115_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21b9bec918a08d0ec5975d21cc2973b4d4ac5c40bd483c903a5879d2b53852c4"

  strings:
    $s1 = "VQpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}