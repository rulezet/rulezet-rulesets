rule Virus_Hijack_GenPack_Backdoor_Hangup_B_473_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_473_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0688e91464bf64e33fe5848ed591eff19bf0706b370d073395ef12f8f5391502"

  strings:
    $x1 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii
    $s2 = "yALPC Port" fullword wide
    $s3 = "Copyright 2022 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}