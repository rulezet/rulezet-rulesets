rule Virus_Hijack_Backdoor_Hangup_B_98 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_98.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b90f037419c21c06eb37e1d0df269a9150c0723bfab15a595fa7c54b51dff42b"

  strings:
    $s1 = "$create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}