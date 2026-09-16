rule Virus_Hijack_Backdoor_Hangup_B_314_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_314_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30dfeb6328c8d6259ffdbc607afe246d334e80a57b6896f0411f1f9ee95abb67"

  strings:
    $s1 = "services. We may also share it with others, such as hardware and software" fullword ascii
    $s2 = "s fees. You and Microsoft agree to the terms governing procedures, f" fullword ascii
    $s3 = "Y;duCk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}