rule Virus_Hijack_Backdoor_Hangup_B_74_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c270d9d4fe633471a65c0ca0f18a08a5e374771562e06713050b28216bfea74d"

  strings:
    $s1 = "(char)('" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}