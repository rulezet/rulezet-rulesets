rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_541 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_541.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc68140e0cf1ebeef6721faecc4f8b440ab16e278b0ec24192416fc84f3af94b"

  strings:
    $s1 = "sare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}