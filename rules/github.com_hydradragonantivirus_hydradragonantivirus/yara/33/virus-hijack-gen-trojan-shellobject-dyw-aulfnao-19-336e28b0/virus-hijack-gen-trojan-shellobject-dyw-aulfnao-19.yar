rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b565c97bfe256f9e2745a0d93c0c9bf08159ce3be5d11a1430d589e6837b2565"

  strings:
    $s1 = ";Flay." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}