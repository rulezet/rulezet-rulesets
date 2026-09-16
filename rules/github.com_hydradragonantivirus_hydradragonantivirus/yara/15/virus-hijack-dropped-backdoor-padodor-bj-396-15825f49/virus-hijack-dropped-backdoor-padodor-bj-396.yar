rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_396 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_396.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b67881c1fbc1b1e3132a1077fffe7107e3b7a06a848f606f4c9a90bc45d3976"

  strings:
    $s1 = "geSt`%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}