rule Virus_Hijack_Backdoor_Hangup_B_160 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_160.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0584db99dc21e7075bbc986c314d9df2791e3c39b666b5fc0f1e88b4d1ade14"

  strings:
    $s1 = "5your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}