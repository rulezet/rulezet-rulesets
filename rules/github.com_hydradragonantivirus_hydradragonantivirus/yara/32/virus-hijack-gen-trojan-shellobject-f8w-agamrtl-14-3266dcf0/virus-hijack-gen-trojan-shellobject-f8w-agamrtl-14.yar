rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a7deb1e9acb83c18a6acf4697537814eef0d63b89ba4533ca1ae246acd5cead"

  strings:
    $s1 = "j\"program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in vio" ascii
    $s2 = "j\"program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in vio" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}