rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "379f3ca092de96cd8f46e858c9ab1dd18e044226e9455b08d85e811e0dc526d2"

  strings:
    $s1 = ":Yprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = ":Yprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}