rule Virus_Hijack_Trojan_GenericKDZ_103285_790 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_790.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e415391912c19763fe5da24e9a82cbbbc257ae300dbb7310ef3693f077ad9672"

  strings:
    $s1 = "ywa?FLaW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}