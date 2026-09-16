rule Trojan_Danger_Trojan_GenericKD_72853156_193_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_193_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bafa97334e2788d2a267588d4555690b5183a3293df7746d243208afeb3cf5e5"

  strings:
    $s1 = "Copyright  Songhares" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}