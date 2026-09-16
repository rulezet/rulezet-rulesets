rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "550882c76889c9b9e092a082022f8e34c27f0c6ab249923d1c16305e5586d051"

  strings:
    $s1 = "=*4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}