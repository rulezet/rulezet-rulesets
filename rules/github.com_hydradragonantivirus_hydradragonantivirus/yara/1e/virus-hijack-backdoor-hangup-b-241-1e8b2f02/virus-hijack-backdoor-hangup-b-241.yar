rule Virus_Hijack_Backdoor_Hangup_B_241 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_241.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b18ab6ec2ae943ab7a99b9b0a9b9de401a8628cc10629f2646534383cf2e970"

  strings:
    $s1 = "vgcounted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}