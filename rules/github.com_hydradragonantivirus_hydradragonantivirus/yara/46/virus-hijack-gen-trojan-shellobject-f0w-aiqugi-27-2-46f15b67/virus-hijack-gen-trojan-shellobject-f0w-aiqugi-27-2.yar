rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_27_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_27_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b6c6c2a764d8fef59455935fa43ac30fe7db543d13f6119a62c5b14faa87325"

  strings:
    $s1 = "hBC\"vAST" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}