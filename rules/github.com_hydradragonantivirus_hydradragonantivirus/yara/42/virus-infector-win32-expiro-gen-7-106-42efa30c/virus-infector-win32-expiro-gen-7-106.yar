rule Virus_Infector_Win32_Expiro_Gen_7_106 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_106.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f4719db08a5bbd54ed43756c65a5a08da9e7bdb05b85b0c8167ae3b71d53086"

  strings:
    $s1 = "h>SuDs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}