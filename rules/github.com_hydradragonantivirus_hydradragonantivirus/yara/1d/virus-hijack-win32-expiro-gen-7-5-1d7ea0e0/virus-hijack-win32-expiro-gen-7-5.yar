rule Virus_Hijack_Win32_Expiro_Gen_7_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Expiro.Gen.7_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18358113628fb6cca820d61337831fb5a601e5f88b92644f95c36ed153d4d04a"

  strings:
    $s1 = "x okEE" fullword ascii
    $s2 = "6*sIsH" fullword ascii
    $s3 = "[Rate`Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}