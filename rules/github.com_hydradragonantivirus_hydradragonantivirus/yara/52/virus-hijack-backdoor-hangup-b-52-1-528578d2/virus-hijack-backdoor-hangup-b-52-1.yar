rule Virus_Hijack_Backdoor_Hangup_B_52_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_52_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afaad5f3aed109b7b11b5f6f6de96600fc2add0907de1884ab51ee9dc76f604c"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s2 = "BOGY'S GAME ENGINE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}