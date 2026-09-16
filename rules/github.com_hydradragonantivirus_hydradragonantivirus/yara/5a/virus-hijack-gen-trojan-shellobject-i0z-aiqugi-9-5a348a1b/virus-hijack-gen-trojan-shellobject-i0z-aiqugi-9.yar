rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a23f6aa18258820e49ae7ed819c27af36287aeb34bcb97072e5b59ad9dac9477"

  strings:
    $s1 = "w54. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}