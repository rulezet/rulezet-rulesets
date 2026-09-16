rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63904074ab63d1996110a756babac3d23f8da6570c44c778a0faff1876e7bd39"

  strings:
    $s1 = "!G4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}