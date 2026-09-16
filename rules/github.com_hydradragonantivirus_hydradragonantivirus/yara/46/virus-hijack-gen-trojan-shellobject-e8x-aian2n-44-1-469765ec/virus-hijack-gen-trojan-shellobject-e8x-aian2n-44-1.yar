rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_44_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6922b683b88493593b5767f8ec0e9076f3ed3a1e7a156575800817ddb7b9e9f"

  strings:
    $s1 = "User-Agent: MIZillA/6.0 (WiNdows NT 8.1; WOW32; Trident/8.0; rv:19.0) like Jecko" fullword ascii
    $s2 = "%s\\360Chrome\\Chrome\\User Data\\Default\\Login Data" fullword ascii
    $s3 = "%s\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data" fullword ascii
    $s4 = "%Rand%" fullword ascii
    $s5 = "Started Date" fullword ascii
    $s6 = "Accept: text/html,application/xhtml+Xml,application/xml;q=0.9,image/webp,*/*;q=0.8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}