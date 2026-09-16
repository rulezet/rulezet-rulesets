rule Virus_Hijack_Trojan_GenericKDZ_105924_388_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_388_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cad919c0c0f1727d2493b15c33f820ccb06a08ec3529504329d341745722f03"

  strings:
    $s1 = "%tiTI {" fullword ascii
    $s2 = "<,tUNe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}