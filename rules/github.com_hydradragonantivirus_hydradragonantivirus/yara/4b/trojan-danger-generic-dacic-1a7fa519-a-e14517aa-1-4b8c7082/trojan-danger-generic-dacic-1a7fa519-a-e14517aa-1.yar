rule Trojan_Danger_Generic_Dacic_1A7FA519_A_E14517AA_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.E14517AA_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b92a4714350051418f587c63a3eed027f3b3c3a11e7fc6742222d5cf6fd2613c"

  strings:
    $s1 = "Z+University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}