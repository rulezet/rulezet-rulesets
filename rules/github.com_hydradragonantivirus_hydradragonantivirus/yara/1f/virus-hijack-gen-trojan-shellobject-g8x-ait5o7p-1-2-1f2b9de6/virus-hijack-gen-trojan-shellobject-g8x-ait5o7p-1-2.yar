rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_ait5o7p_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@ait5o7p_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fc4b2806e613d1d31ab530c2733ff06223fd637cbce0a2b9daecca6c3648951"

  strings:
    $s1 = "\\My Shared Folder" fullword ascii
    $s2 = "Baga]s" fullword ascii
    $s3 = "`Write" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}