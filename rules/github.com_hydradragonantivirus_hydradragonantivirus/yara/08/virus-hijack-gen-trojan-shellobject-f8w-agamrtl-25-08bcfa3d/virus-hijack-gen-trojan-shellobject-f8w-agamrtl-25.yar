rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55b07fe91a72a7b5cfddd3d7d25478ee039b25ebeea4532ec1e0f467d7a51147"

  strings:
    $s1 = "J\"program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in vio" ascii
    $s2 = "J\"program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in vio" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}