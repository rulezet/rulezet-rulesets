rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efe5ac8b64cabb416f26d303b2b4c6408f7c3c42dffb56d871e02dd4590f0278"

  strings:
    $s1 = "iN4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}