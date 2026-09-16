rule Virus_Hijack_GenPack_Backdoor_Hangup_B_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0dc7015a450db94194526ee70bd4c433a2abb6ac7c0f62ba794422431c086e4"

  strings:
    $s1 = "2qsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}