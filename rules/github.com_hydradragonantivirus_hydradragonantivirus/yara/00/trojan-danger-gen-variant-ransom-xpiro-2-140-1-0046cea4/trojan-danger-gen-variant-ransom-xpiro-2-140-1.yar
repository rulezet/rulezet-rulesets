rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_140_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_140_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0221f948c18b186a886f459ec21ff3a9a89efff8866e48bc633a055518b08bf8"

  strings:
    $s1 = "8Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii
    $s2 = "n>BUSS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}