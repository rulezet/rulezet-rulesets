rule Virus_Hijack_Backdoor_Hangup_B_217 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_217.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be41082759b56c70a68e45fe21a7ddefff46d09186365cd92494975345992953"

  strings:
    $s1 = "Osoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}