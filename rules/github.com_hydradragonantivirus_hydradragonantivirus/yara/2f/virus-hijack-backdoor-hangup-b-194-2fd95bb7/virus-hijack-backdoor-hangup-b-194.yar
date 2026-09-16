rule Virus_Hijack_Backdoor_Hangup_B_194 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_194.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "880f92f365ab55cb2ee94f51d85379fe7b6a8092daa5d6f9dff408c07221c30d"

  strings:
    $s1 = "R_counted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}