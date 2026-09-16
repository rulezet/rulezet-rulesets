rule Virus_Autorun_Gen_Variant_Doina_Blind_11663_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Doina.Blind.11663_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0444edb98496a028884b39ca629db0f5b7977f7fafa32789ed6c1f31b33f5f2e"

  strings:
    $s1 = "PSNR NTP Host Company" fullword wide
    $s2 = "PSNR NTP Space Provider" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}