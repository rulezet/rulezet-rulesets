rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_104 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a444156b500dda968b1e558aa6fdcc6669831b4b5240a1095fcf019776c4b97"

  strings:
    $s1 = "(T4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}