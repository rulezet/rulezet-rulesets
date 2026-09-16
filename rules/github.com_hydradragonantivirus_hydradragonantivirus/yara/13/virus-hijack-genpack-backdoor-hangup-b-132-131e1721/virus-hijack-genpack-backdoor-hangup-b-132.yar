rule Virus_Hijack_GenPack_Backdoor_Hangup_B_132 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_132.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c37b801c2d7d25f3acec924fee7b689780482c057499d96333df2a65993e8b"

  strings:
    $s1 = "zsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}