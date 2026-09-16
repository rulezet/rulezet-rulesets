rule Virus_Sysbot_Gen_Variant_Application_Jaik_Dridex_39019_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Application.Jaik.Dridex.39019_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8b24460cbbe583181c684610302603801c9fc9951287d8e2974fbde52b69189"

  strings:
    $s1 = "9j\"lamb" fullword ascii
    $s2 = "gout,y" fullword ascii
    $s3 = "P>talL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}