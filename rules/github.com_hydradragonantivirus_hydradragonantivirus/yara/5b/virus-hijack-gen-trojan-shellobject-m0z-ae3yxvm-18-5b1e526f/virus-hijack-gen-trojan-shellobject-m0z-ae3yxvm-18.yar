rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbcb6f2cef5004f6ce58eecd6675f2a5d9a432d648f104f4d388efa757820b3d"

  strings:
    $s1 = "L]4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}