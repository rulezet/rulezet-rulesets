rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25e62db685a88539575f634f383892f1fd01cdc9436e5a2b4fd7656e5999c3e3"

  strings:
    $s1 = " w4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}