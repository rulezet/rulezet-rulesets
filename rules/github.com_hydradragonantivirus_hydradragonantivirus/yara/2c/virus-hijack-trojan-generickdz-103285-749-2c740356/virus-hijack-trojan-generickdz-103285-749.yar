rule Virus_Hijack_Trojan_GenericKDZ_103285_749 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_749.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "743b616199f2e472cd796c85721ee13731f7909d85ae8c2271bf10f7a90ae764"

  strings:
    $s1 = "<What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}