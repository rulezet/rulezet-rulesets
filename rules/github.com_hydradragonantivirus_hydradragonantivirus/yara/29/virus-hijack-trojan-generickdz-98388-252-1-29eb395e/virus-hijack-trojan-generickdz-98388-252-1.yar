rule Virus_Hijack_Trojan_GenericKDZ_98388_252_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_252_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc3cd4c885678f2d17be692669636faf25092f89f2e4d3b0d6f599a6acec01fe"

  strings:
    $s1 = ":H'HIS@orad$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}