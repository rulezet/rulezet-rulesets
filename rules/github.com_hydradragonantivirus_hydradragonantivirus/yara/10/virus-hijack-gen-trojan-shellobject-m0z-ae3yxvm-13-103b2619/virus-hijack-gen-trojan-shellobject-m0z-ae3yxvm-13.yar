rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54323f8997cbbea53af6fc35dbb752ba57458284aa9a34fe77796c9e440419fc"

  strings:
    $s1 = "'4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}