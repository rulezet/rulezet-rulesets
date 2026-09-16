rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_783_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_783_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2de233da33824e81de85c3216aef32f6b760cc2946f16a2b251aa952f2f989ac"

  strings:
    $s1 = "akinesia" fullword wide
    $s2 = "Roundwood" fullword wide
    $s3 = "Grison" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}