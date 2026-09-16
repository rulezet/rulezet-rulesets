rule Trojan_Autorun_Trojan_Ransom_Doboc_A_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Ransom.Doboc.A_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9b6851fa80bda9db2718aeadcff4e99898cb3134bd0649641e38ecaab324eba"

  strings:
    $s1 = "WKprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "WKprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}