rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c76106fbb36d79441ced9682ba587fa04bf5b77b8e5c5e10d9d88d05ffdd4a98"

  strings:
    $s1 = "z4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "CHaR( " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}