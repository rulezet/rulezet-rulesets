rule Virus_Hijack_Backdoor_Hangup_B_224 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_224.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d6bf6c0dc6511a793714761e56434034cb41fae2677de292ef0a4f2fce4291d"

  strings:
    $s1 = "$}your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}