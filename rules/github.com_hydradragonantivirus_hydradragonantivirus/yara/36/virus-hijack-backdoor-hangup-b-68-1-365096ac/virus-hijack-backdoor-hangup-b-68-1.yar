rule Virus_Hijack_Backdoor_Hangup_B_68_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4b0dfc877a40cd9d9b891b77585a6e0c20e2f0093e62d3e02962149e81a0be4"

  strings:
    $s1 = ":@ByELDI Certificate Authorit" fullword wide
    $s2 = "HALl}/" fullword ascii
    $s3 = "?!Send" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}