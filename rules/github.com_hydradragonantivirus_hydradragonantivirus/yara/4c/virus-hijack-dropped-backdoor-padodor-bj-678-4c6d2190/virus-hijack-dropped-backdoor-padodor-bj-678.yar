rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_678 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_678.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb815951f49f78c3be685161a08d793f6188e3c9e95cd150fb57e7deb2ed1039"

  strings:
    $s1 = "}Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}