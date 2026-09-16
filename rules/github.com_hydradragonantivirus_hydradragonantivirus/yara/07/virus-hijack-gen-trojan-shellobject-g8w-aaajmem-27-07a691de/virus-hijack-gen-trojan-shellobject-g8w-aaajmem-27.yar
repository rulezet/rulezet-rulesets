rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bb5a921dd5e79ef4dbfd21a5ff5882fe60a514e90013151dcdff83db03bf07f"

  strings:
    $s1 = "JuWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}