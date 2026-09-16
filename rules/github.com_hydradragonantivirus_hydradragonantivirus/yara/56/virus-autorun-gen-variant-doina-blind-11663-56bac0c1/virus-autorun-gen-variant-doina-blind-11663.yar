rule Virus_Autorun_Gen_Variant_Doina_Blind_11663 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Doina.Blind.11663.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b99a0d81be08c1535cc7f2357be7e283ce66999dae73087cd657d344889c544f"

  strings:
    $s1 = "PSNR NTP Host Company" fullword wide
    $s2 = "PSNR NTP Space Provider" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}