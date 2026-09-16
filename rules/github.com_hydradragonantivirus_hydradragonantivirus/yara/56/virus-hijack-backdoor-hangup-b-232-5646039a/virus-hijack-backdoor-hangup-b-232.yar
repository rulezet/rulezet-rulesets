rule Virus_Hijack_Backdoor_Hangup_B_232 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_232.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94d9e5c6ba1aed7d3f1a5fd2ccc66ce7a077427b526f769c397abcb4ea504df3"

  strings:
    $s1 = "gOcounted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}