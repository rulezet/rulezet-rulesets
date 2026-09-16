rule Virus_Hijack_Trojan_GenericKDZ_74550_387_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_387_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20ce534a197908a2dc60164f224d97cb1358887c6ab9ca7a9d0558cfec48cdb7"

  strings:
    $s1 = "Dorn:I=" fullword ascii
    $s2 = "4!HarM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}