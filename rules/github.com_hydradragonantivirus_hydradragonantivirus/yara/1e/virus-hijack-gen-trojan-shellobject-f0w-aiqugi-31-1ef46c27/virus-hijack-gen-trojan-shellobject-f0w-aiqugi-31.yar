rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43970eeee6cc67938b640aa1fe7f4ef479667b741585129a1b94a5343935cd7b"

  strings:
    $s1 = ")4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}