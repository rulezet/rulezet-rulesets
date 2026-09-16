rule Virus_Hijack_Gen_Trojan_ShellObject_e4X_a8K8N6h_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4X@a8K8N6h_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ef13ad23d38efe11822cb7e7f4d9ae00092ff93802924f46f6afde0634c7606"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}