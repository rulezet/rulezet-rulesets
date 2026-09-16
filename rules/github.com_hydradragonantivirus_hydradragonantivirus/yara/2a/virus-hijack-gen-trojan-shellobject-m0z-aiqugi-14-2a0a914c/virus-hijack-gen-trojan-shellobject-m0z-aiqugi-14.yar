rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b6833f82d2e5f79acdbe28d3e00ae2b69fa09f1ee6914e169bf95c15a79568f"

  strings:
    $s1 = "S4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}