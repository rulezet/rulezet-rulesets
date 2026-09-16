rule Virus_Hijack_GenPack_Backdoor_Hangup_B_120 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_120.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "984cf324275c49eebc06f932f49214a3b89ad5eb3f409980e7c6414740e2b509"

  strings:
    $s1 = "|software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}