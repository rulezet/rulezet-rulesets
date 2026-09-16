rule Virus_Hijack_Backdoor_Hangup_B_292_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_292_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57abacfd1507718f8f98c15f20af30422a499f9df9125b50b1173c076fe2246f"

  strings:
    $s1 = "H. Technical Supportuq1bxbv35pm386trhhrn98rbv44td6462509n50rkpaafwm664bc48h4v0ap506j85ge7be86ei9n083c547f11h2f2piw8854p061t05b9n" ascii
    $s2 = "Virtual@L" fullword ascii
    $s3 = "H. Technical Supportuq1bxbv35pm386trhhrn98rbv44td6462509n50rkpaafwm664bc48h4v0ap506j85ge7be86ei9n083c547f11h2f2piw8854p061t05b9n" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}