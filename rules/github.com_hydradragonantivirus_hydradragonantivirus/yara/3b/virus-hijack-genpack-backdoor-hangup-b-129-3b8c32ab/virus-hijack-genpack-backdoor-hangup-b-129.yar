rule Virus_Hijack_GenPack_Backdoor_Hangup_B_129 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_129.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2be48331cb775ccc02e78e976bc4f0e47c0bd24cfeeea3b54fdf3e6155ab9047"

  strings:
    $s1 = "fyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}