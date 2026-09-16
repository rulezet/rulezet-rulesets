rule Trojan_Danger_Trojan_GenericKD_67064203_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67064203_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46a1f53a5a29bd1e667a9ae6ddda8a831754b471508adf2674457f87578f0ed0"

  strings:
    $s1 = "MiMa$jB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}