rule Virus_Hijack_Gen_Trojan_ShellObject_6zZ_aWcfH4h_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.6zZ@aWcfH4h_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cc2866997ae71ba3770a12d6c17cde2e299c302a4fa4f3a7714b7264e0b43c1"

  strings:
    $s1 = "613;gj>8>9;CorF@FACKwzNHNIKS" fullword ascii
    $s2 = "f`fack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}