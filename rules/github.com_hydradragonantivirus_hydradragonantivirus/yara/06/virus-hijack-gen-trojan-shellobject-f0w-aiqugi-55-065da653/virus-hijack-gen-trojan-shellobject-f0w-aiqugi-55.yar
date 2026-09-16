rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_55 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "688b30cf01e50b87cd4562856fa401649d89ff6810dd1d55b028ca93bc925590"

  strings:
    $s1 = "h:4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}