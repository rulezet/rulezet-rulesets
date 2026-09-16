rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_328_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_328_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c6f3c609fd5e632341691e549d2f9159ae05e400fecf0d6538d760c47dbcde2"

  strings:
    $s1 = "Browser Version 1.0" fullword wide
    $s2 = "About Browser" fullword wide
    $s3 = "Browse Document" fullword wide
    $s4 = "Performance Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}