rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_85_2_Virus_Hijac_263 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash2       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash3       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash4       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"

  strings:
    $s1 = "%s: Failed to find '%s' key in new format JSON file while deserializing ASNP" fullword ascii
    $s2 = "%s: Failed to find '%s' key in old format JSON file while deserializing ASNP" fullword ascii
    $s3 = "%s: Failed to find '%s' key in new format JSON file while deserializing OC" fullword ascii
    $s4 = "%s: Failed to find '%s' key in old format JSON file while deserializing OC" fullword ascii
    $s5 = "%s failed in deleting certificate from store" fullword ascii
    $s6 = "%s failed in serializing certificate context" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}