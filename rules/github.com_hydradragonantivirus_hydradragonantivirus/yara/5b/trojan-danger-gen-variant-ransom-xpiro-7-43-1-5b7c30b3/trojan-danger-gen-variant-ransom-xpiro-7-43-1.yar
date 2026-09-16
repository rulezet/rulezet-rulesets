rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_43_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33255b6f51c665770ee7d320246444b3383c228ea340efcc266f7d0ec2e45be3"

  strings:
    $s1 = "uSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}