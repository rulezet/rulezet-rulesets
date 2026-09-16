rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be5e3093e3d362bb750826e0184d41a135186ffb36421200d2aae3f02b6b0bed"

  strings:
    $s1 = "5.0.6 @Commit: 478b2f8c0e480665f6c52c95cd57830784dc9560" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}