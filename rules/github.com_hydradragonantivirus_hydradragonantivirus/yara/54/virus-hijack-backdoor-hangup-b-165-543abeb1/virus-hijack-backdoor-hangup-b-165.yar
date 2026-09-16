rule Virus_Hijack_Backdoor_Hangup_B_165 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_165.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e32dad1b39c413e12e8e2be0f8ac70ef2cc5d08a1acb1d2c1f140c89b1bdf6c"

  strings:
    $s1 = "Fsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}