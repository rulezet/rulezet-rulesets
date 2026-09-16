rule Virus_Infector_Win32_Expiro_Gen_7_175 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_175.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa6a7930b07ec077be6fa61998113d13e629c8520205466f3e380769f95d68b7"

  strings:
    $s1 = "bENA!\"" fullword ascii
    $s2 = "MULE]gF" fullword ascii
    $s3 = "swAG$J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}