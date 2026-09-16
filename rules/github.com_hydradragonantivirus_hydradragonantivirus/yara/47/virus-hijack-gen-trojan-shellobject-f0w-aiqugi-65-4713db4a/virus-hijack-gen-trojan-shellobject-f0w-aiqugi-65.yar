rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_65 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_65.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27f642a039c34611b92ac111c4b91d293f615aed6cdeb1fb86a3966601d149bd"

  strings:
    $s1 = "V4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}