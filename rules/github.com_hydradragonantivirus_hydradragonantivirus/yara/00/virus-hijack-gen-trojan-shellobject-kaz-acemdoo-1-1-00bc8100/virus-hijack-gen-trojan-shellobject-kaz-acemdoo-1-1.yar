rule Virus_Hijack_Gen_Trojan_ShellObject_kAZ_aCEmdoo_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.kAZ@aCEmdoo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d22a18c2e9e71904cdde2f9b56a060e82b2fda7f6a1d99319b8158508700779"

  strings:
    $s1 = "; name" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}