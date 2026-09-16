rule Virus_Infector_Win32_Expiro_Gen_7_202_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_202_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "106d93ced41d81795f66bb29ad5c847a25a1e2c094fe28a67dc576f1c33fcad4"

  strings:
    $s1 = "Run Once" fullword wide
    $s2 = "\"cLAY@p2h Q5A" fullword ascii
    $s3 = "Chrome 5" fullword wide
    $s4 = "aute{kfknclputejkfkn" fullword wide
    $s5 = "Run Always" fullword wide
    $s6 = ">*pYrE" fullword ascii
    $s7 = "eXeAt;" fullword ascii
    $s8 = "Calculator Installation" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}