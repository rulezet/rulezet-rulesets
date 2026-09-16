rule Virus_Hijack_Backdoor_Hangup_B_296 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_296.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42cd7cbea162f093c0f57ef79b9a21ceb74a3ae87c9afb9369f54cad44410021"

  strings:
    $s1 = "+counted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}