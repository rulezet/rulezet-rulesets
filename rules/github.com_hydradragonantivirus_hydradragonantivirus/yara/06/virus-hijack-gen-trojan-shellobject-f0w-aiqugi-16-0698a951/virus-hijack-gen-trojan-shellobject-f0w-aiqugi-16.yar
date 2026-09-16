rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6acf4302f6809d41d089e988c178096f66708f942c2871d8b03d16bc5b7007d4"

  strings:
    $s1 = "!B4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}