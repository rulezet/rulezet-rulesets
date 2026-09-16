rule Virus_Hijack_Gen_Trojan_ShellObject_A8Z_a0oa39p_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.A8Z@a0oa39p_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b795a5b0767e4b1afe40168ae197b8509461d0e06b0876a8e8c9d4f9bd87b1ce"

  strings:
    $s1 = "enough spasw" fullword ascii
    $s2 = "base >," fullword ascii
    $s3 = "2ge9g8?;:omAo@GCBwuIwHOKJ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}