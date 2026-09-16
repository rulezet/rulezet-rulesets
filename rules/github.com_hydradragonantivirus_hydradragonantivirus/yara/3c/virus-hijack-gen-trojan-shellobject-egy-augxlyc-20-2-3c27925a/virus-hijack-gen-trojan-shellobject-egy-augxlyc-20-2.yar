rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_20_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_20_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295874510bc06125746ae8ffcea35727212e9091d4eb5e2bb99bc69567879353"

  strings:
    $s1 = "{AwAY +s/'+.(g*g-" fullword ascii
    $s2 = "Inserted " fullword wide
    $s3 = "About SaferoadApp Inc." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}