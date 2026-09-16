rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0af2ba9e369c4b246289f61e147605a6b48fcc683c3448439120bfdd70095843"

  strings:
    $s1 = "rWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}