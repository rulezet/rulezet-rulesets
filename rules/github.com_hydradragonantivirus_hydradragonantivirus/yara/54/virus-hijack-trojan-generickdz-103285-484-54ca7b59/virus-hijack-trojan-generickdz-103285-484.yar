rule Virus_Hijack_Trojan_GenericKDZ_103285_484 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_484.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d29cb8c7d323bb9100447d3946f5054febb76822b4b2cc3445eabbd2afeff560"

  strings:
    $s1 = "yqpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii
    $s2 = "If you have a dispute with Oracle or if you wish to provide a notice under the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}