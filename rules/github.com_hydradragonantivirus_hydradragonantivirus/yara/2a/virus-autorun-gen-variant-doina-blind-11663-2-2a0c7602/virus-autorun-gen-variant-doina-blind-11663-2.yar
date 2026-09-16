rule Virus_Autorun_Gen_Variant_Doina_Blind_11663_2 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Doina.Blind.11663_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3520c4887dc1f82a72c4354fd8268a3a869a51013b199ab5929abf9aa2fcea2"

  strings:
    $s1 = "PSNR NTP Host Company" fullword wide
    $s2 = "PSNR NTP Space Provider" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}