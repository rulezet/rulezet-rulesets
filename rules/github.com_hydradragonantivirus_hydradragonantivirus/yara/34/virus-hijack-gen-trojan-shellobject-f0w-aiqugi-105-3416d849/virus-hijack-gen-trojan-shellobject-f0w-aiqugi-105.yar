rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_105 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef1c17485b6c83112c4ca4933034bbad958630d40339975891329b4f2bdd1656"

  strings:
    $s1 = "04. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}