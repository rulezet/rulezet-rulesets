rule Virus_Hijack_Trojan_GenericKDZ_74550_185_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32e7a93547b83ffe82476a0daa9896cbb1277a493319f1d8da94670f84f311e1"

  strings:
    $s1 = ":JaKO<," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}