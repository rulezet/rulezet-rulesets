rule Virus_Hijack_Backdoor_Hangup_B_75_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76a16267140c33bc8afacc47e599f3d9aee6f5c3f017ec12238d4710546f5f05"

  strings:
    $s1 = "(char)('" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}