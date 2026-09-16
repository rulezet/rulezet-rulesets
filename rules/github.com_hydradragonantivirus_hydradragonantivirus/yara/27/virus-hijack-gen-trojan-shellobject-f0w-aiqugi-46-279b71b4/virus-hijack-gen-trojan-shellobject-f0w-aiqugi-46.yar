rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_46 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18afceef934b0060ceb9d3cd3bc373de184dc4400dc9e6f2b74c57e78e04fac8"

  strings:
    $s1 = "n4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "s+HLfv]Ar=CT.4BCa,DOne" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}