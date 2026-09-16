rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_110 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_110.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf88f21ac7df11f6b261266d7114b1f708eb735d429803cf4b7555dbda786834"

  strings:
    $s1 = "9-4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}