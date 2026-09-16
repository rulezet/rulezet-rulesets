rule Virus_Hijack_GenPack_Backdoor_Hangup_B_39 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "486538ae7e8498123dbe321468a974aafec9c8ea946d3c5a44c0d5feb8dc6d5e"

  strings:
    $s1 = "usoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}