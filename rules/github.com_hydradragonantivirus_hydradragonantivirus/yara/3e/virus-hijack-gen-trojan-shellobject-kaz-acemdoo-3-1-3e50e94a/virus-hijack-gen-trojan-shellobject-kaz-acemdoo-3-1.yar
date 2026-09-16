rule Virus_Hijack_Gen_Trojan_ShellObject_kAZ_aCEmdoo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.kAZ@aCEmdoo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce8565d23873b4112e209eadccef3e3436f3d766375c2a8974f8de62df6c3943"

  strings:
    $s1 = "; name" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}