rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74970636704f6fa3df24d9f2cbca945a71f6e5d2cf663b4951e6df055b7b7e36"

  strings:
    $s1 = "(4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}