rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7670cf1928f9c5ff1335e58b01e752f917357a5659e8113d000cf7d5c1653041"

  strings:
    $s1 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}