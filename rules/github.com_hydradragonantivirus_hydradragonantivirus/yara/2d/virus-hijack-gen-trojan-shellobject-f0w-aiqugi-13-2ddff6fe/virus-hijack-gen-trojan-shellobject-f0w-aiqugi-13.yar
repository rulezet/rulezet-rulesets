rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdccfa6b6d1fe69c9621a880d5affe8a1a2aea53bdac3e3df2ecc1f06b0075f3"

  strings:
    $s1 = "F4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}