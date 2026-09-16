rule Virus_Infector_Win32_Expiro_Gen_7_26 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3209577ec2a64583b08990c2b9b157e00696a54d6a639c7b5f2aab7083a23312"

  strings:
    $s1 = "E:MOko" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}