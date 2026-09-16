rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87eb75c37cae5daafdaed91e1ada1c377d8b423d35b1ba9a22c2130acf1f12f8"

  strings:
    $s1 = "Np4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}