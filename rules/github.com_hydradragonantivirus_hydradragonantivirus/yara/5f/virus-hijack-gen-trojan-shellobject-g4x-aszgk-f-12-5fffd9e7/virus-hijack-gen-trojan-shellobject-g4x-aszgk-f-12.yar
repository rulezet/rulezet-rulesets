rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a9f7220d08b0142464a96096757761dfbd8b48bf57e29f4ace8e2c1771e6e2f"

  strings:
    $s1 = "%Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}