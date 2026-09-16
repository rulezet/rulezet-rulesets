rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_101 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_101.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b82587feff93a351ba799a74628bba0becb561c75d121c3dd866d8c5f7f35c1"

  strings:
    $s1 = "v4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}