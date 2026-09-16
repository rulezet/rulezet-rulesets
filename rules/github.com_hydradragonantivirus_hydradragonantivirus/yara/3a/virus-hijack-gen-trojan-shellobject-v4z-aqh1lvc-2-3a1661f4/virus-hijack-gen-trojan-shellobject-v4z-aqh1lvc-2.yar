rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "545b9e4231b74899e0db33a7ba841a18a9e95c65c81676229b39edeac44b1bb2"

  strings:
    $s1 = "2Nmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}