rule Virus_Hooker_Trojan_Generic_30984256 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.Generic.30984256.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceaba380ecb3f2d19e2741acbc4a2e58371f5490d4cbd4a13eda3dd713b9db38"

  strings:
    $s1 = "|\\(WheT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}