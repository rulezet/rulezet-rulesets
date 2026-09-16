rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60fa080812194cb9a27ecfd5e6c8f04d33fe4eff9cd6bc2633e3a563b18e0977"

  strings:
    $s1 = "^4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}