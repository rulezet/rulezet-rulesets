rule Virus_Hijack_Gen_Trojan_ShellObject_GuZ_aiy413e_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GuZ@aiy413e_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b37eae58d62b2d33e400892b1fd9262c2c943dae5480c349ca2304a19d61ac3a"

  strings:
    $s1 = "Overhasty" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}