rule Virus_Hijack_Trojan_GenericKDZ_103285_59_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_59_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60493bcd6c81157ed5b621af755338734d13f3b180d5bc8dd95f0870a022e66e"

  strings:
    $s1 = ".IEC 61961-2.1 Default RGB colour space - sRGB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}