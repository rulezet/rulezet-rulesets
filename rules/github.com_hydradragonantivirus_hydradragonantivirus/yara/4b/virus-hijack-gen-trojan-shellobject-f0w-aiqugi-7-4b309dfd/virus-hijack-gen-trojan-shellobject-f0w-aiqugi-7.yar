rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a531b2c220d90d660138fb3ab221f0f1daff978fab6d98feb6d4f1ba68408772"

  strings:
    $s1 = "L4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}