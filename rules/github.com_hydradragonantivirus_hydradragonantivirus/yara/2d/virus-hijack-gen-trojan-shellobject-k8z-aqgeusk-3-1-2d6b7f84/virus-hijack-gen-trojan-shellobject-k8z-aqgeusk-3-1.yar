rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aqgEuSk_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1af52203bcb589a9da8b6a7d0a9a7da4974fc841ff73500315ada4362a51aae1"

  strings:
    $s1 = "==******************************************************************************************************************************" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}