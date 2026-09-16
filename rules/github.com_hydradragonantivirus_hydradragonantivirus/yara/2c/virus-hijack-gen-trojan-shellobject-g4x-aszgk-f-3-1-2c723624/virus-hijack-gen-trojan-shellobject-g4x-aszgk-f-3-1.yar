rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f65831f3e97cb6f30e564eb205c238c9b7acda56494489fdc49f46df7992d510"

  strings:
    $s1 = "narK?p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}