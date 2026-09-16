rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad853108b7bbef5150feb795726a4c34fe47334d535be11d5e7c877357e49e7e"

  strings:
    $s1 = "NJ4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}