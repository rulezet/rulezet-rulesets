rule Virus_Hijack_Backdoor_Hangup_B_150 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_150.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6214d1d32998134f9b505e0c33775a4913209f75ef48772a299ea70f08dbded2"

  strings:
    $s1 = "Csoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii
    $s2 = "jimP%i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}