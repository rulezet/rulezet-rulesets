rule Trojan_Danger_Generic_Dacic_1A7FA519_A_2D3D82A8_16_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f3ef1ef6caa5ec0798d7ff3d7a8dcb1d4e6fb4a1f915335bb2c49adc356a180"

  strings:
    $s1 = ";%Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}