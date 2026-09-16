rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa966e22c0d2fec24634345d9cb499384165a0442bfa9943cdd679c443e049c3"

  strings:
    $s1 = "\\/4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}