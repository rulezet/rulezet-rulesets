rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_83_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_83_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bd62a9747edf2dde642d38855eac9949557968d6585182a05b00ed9497a123d"

  strings:
    $s1 = "underfeeling" fullword wide
    $s2 = "Morrowmass" fullword wide
    $s3 = "Abstractiveness" fullword wide
    $s4 = "HALA@ED" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}