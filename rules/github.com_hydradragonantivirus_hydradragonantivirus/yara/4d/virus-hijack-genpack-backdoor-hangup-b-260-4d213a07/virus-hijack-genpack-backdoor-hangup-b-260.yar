rule Virus_Hijack_GenPack_Backdoor_Hangup_B_260 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_260.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89f4174a376058bc3d5f3fb3cbfdf02895330ec0e683bdeb35f6e92fc624d539"

  strings:
    $s1 = "lISt#O9t#K9t#O;tIO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}