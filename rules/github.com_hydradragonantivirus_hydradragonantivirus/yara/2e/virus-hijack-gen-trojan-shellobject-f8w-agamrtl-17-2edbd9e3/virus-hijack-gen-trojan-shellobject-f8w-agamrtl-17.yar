rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f278a64d516cf31be1422ce3cfb8e7ff523135fd3d067bb41baa3d801e31060f"

  strings:
    $s1 = "Cdprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "Cdprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}