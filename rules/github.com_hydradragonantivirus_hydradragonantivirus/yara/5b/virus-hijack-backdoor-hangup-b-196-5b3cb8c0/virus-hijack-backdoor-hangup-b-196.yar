rule Virus_Hijack_Backdoor_Hangup_B_196 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_196.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d8bc132d1dcf1f4293411002465ca84e65c7168a2a9a1967acdee00ffb74880"

  strings:
    $s1 = "Eyour entire employee population." fullword ascii
    $s2 = "]SaDe;" fullword ascii
    $s3 = "H)SaMp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}