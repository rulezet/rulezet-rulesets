rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_784_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_784_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94921ee421c03f4b5dc020260580651e88f4c8d5242014b00a42471656f9c15e"

  strings:
    $s1 = "akinesia" fullword wide
    $s2 = "Roundwood" fullword wide
    $s3 = "Grison" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}