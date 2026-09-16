rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "664b1e842035d9765ba59f21ff84585f4dfb28af6ef3d89d4d0088eb8d24e0af"

  strings:
    $s1 = ":4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}