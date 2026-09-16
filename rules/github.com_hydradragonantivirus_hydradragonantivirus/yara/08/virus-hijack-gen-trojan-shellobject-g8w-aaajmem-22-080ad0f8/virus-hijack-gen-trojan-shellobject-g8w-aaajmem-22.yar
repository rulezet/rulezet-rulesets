rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "938ba283d91d51d9679185ecd12b68361b1d36c3312c56f352228e6af5635e0a"

  strings:
    $s1 = "4What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}