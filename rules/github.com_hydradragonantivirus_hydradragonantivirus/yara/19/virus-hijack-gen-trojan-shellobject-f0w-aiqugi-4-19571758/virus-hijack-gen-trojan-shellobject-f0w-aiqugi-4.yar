rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b07bb99e6e754c880660baee11bd7a01fc51106ac7bd233b4c5f5ffa2f3795c"

  strings:
    $s1 = "}4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}