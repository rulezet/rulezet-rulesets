rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efead46242f9911a561f276baabad01481ef77acdbf856139ff984a16911c408"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET CLR" wide
    $s2 = "gzip,delate" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}