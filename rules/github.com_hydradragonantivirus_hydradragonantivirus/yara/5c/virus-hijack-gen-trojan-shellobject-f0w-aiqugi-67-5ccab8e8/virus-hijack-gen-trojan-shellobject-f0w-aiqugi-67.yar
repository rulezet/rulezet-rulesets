rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_67 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_67.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f6ab44bc2d79f9c1bd1215d4a76cb693eef1cf24cd67f1c00dc391387a67e4c"

  strings:
    $s1 = "e{4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}