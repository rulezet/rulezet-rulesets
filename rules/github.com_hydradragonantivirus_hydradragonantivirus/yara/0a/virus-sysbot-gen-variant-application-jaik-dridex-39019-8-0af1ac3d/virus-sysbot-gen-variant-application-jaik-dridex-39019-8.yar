rule Virus_Sysbot_Gen_Variant_Application_Jaik_Dridex_39019_8 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Application.Jaik.Dridex.39019_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7562056951b1f1267a25b6a6585beec617f7528a8e724ca5ead3e3032cc3e20a"

  strings:
    $s1 = ";&soDY?" fullword ascii
    $s2 = "sniPe&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}