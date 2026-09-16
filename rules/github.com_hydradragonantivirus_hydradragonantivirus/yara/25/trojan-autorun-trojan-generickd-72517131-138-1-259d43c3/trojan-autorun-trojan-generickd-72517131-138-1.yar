rule Trojan_Autorun_Trojan_GenericKD_72517131_138_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_138_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad2c166fe52bee345f638bb386a314d769940e92eb1a7153eda5f6f48f1455f7"

  strings:
    $s1 = "pQUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}