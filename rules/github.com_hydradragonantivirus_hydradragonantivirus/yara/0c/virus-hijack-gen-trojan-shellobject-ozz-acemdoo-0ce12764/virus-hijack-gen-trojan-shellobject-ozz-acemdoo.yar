rule Virus_Hijack_Gen_Trojan_ShellObject_OzZ_aCEmdoo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.OzZ@aCEmdoo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d836f028055850cbb1d420ef9de09a546841e3fcc1d7482e2f85f4f2e9a6c644"

  strings:
    $s1 = "[.}SMavSOObY@\"tUNa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}