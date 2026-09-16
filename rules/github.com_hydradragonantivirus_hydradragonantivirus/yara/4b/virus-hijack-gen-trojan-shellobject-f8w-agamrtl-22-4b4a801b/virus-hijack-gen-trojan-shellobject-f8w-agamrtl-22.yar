rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62eb2066ecc8d1ace50da73918cd8a8751f6ce262f12f0f1ab04a216c4a898ae"

  strings:
    $s1 = "KHprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "KHprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}