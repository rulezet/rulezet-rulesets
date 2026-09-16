rule Virus_Hijack_Gen_Trojan_ShellObject_h8X_a0kuefc_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "903603051a5fe02ee167e6aff5a66cacfa762212673e959c4a9fc50cdebeba27"

  strings:
    $s1 = "+virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}