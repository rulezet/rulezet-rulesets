rule Virus_Hijack_Backdoor_Hangup_B_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dda0f7d8edeadbe2f61f1257fd3972725a936b738fa06f718a8655f7ccc709a9"

  strings:
    $s1 = "6Psoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}