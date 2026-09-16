rule Trojan_Hooker_Gen_Trojan_ProcessHijack_iIZ_ayW08hbb {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Trojan.ProcessHijack.iIZ@ayW08hbb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe3cb83a598bd86a2bd9864d70f90ab1d6efc67bf2882d1a799f9c33020e3386"

  strings:
    $s1 = "TTTTTTTTT begin" fullword ascii
    $s2 = "ZZZZZZZZZ begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}