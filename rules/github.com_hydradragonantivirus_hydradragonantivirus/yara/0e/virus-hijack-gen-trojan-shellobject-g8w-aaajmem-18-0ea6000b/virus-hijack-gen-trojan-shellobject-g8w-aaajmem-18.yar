rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12df6f97a29098f375654966e8b9ca49e0bc33254070ea51fb74010f4e579e1f"

  strings:
    $s1 = ">What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}