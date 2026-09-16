rule Trojan_Danger_Trojan_GenericKD_72304918_140_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_140_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a942a87f0dd9fbb1d59911e889b42a5563b5b44eb1cf9b2542e723a63ec26f7"

  strings:
    $s1 = "<dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}