rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_212 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_212.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85504da5d46135b3518bb92ba0daa32bd0dc63e4052e488f52f35089bc577c32"

  strings:
    $s1 = "s}and services at the list price in effect at the " fullword ascii
    $s2 = "infringement claim could have been avoided by`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}