rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_753_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_753_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "510581f63ca03386e65f6743b47d964c964e70d7a30fecf9cba713e95dbd2b84"

  strings:
    $s1 = "]OkEe?P<" fullword ascii
    $s2 = "1&Glow" fullword ascii
    $s3 = "bluR'," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}