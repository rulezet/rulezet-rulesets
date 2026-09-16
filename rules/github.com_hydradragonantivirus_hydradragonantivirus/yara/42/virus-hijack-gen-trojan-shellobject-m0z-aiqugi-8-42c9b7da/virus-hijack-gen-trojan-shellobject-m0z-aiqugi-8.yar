rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61f3d93988fd6a93d7fd69c3dd1a8ea5ecd45ad257fd3afe261954cdc47be7d0"

  strings:
    $s1 = ";_4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}