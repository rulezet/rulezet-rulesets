rule Trojan_Danger_Trojan_GenericKD_72853156_471 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_471.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8df040ecefb727707e8eec932080d6d80e8ef0f6b896e4ea8673b82884e4e3d4"

  strings:
    $s1 = "oUTfiT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}