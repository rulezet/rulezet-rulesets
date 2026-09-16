rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_84_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_84_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61f169d3e5f120d78c67d1a2c2f1c634d7eac3eafa2edf23f5faf1cb1eff59ee"

  strings:
    $s1 = "}9Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}