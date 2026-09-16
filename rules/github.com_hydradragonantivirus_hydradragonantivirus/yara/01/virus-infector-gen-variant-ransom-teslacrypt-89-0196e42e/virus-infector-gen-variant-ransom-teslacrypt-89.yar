rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_89 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.89.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb6eafe4371cec26189bc3dd2bf96b4b08993d690a147198928d191ac12881f2"

  strings:
    $s1 = "!This program cannot be rGXBCD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}