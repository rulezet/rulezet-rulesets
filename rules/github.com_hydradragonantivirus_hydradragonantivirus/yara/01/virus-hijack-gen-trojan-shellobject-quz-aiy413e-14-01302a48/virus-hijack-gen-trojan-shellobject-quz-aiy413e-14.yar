rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "774b98c76776ef0861ca0147714261e48b5fa114d803df8a6c0be8b26c80b4ff"

  strings:
    $s1 = "}z*mIty(" fullword ascii
    $s2 = ".\"baWD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}