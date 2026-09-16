rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au4JtZd_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au4JtZd_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b0e8061de86e2bf422fbd3710f7c7da332371787f71bc2f81a8ba609b39ff4a"

  strings:
    $s1 = "!Error Down" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}