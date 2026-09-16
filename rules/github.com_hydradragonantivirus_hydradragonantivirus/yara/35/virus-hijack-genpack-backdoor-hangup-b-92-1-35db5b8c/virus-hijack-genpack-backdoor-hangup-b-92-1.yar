rule Virus_Hijack_GenPack_Backdoor_Hangup_B_92_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "305f622ed36a0d1df4c8a153afc1573a3bd052093560ce24b3b63d1dcff9e822"

  strings:
    $s1 = "Adobe Photoshop3" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}