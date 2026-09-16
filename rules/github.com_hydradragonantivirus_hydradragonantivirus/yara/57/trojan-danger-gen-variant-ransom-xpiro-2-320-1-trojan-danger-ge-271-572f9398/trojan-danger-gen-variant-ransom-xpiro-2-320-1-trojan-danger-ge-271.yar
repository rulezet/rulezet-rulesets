import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_320_1_Trojan_Danger_Ge_271 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_320_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_321_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_322_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_323_1.vir, Trojan.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A.vir, Trojan.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_1.vir, Trojan.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_2.vir, Trojan.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_3.vir, Trojan.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_4.vir, Virus.Hooker _Generic.Dacic.6AAA6DD3.A.E33A450A.vir, Virus.Hooker_Generic.Dacic.6AAA6DD3.A.D49F597C.vir, Virus.Hooker_Generic.Dacic.6AAA6DD3.A.D49F597C_1.vir, Virus.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A.vir, Virus.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_1.vir, Virus.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_2.vir, Virus.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_3.vir, Virus.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01280a55db5d1f8ee1ab09175db2b70b89f9c5420c513852e010a7db66f40416"
    hash2       = "c60729278da5a511b2dc41750357b37dba13267f19dd004bb0e51f6978aaf419"
    hash3       = "a4e36237642a90233c104a9be7085405f6e456b0e9f1e98b16f50e2bd73efb89"
    hash4       = "8bb548fabff7a5e50a6d88f63719942df36b492571ddf2f0968c052f9e20a875"
    hash5       = "61928168f9ef0ebfac46344ee2b515125de064bf9bbf17123cf0a140de8298a9"
    hash6       = "9e8f8f0a333c31f693f41ededddc5d38df84f4fecd66931a3754f95ecccb9d42"
    hash7       = "bc57142295cf0620583815ba490ddb7d780454aae21de4cc5b56e49ced40d4e7"
    hash8       = "78c84cc554bef4533db7509928003116877e458e836867399d63dbc7a5b0165f"
    hash9       = "55e67e984d2277c5454b26c15f874e5a002c1cf76f5e727d96cf7b4d7a43c023"
    hash10      = "1f40573aab240586b973de7c593620bb4cb7fd97adbd09966490edebda882565"
    hash11      = "7aa5c78a3b4ab2cc86dae6909bc9f131bb8f5f4182cfc645f7d40774d3ee1e95"
    hash12      = "8935b84bfc83fe6ea01d3083dd0258fb9708afbd90310b8539a4be6cea41e894"
    hash13      = "e7db6a159453b9783d5f8311dda09a40a09cff59a8237fad66c84b2a4d31daf6"
    hash14      = "49cd07eaf49d6bf69570eb1e87f59a8bfb77d67e96d76f3ddf6bee56972d6552"
    hash15      = "d913698ab584eff892d4da6c38027c04ffca02113855efad9f2f743c1db1e7bf"
    hash16      = "8e45ea1b3e881459ff2a4c34a7ca56b4c58c0b395b523f846954297da70e3763"
    hash17      = "31cba12c0c2128ea501612959c9f2d0dd84cae7a9986fe2b90baa37c6909c59f"

  strings:
    $s1 = "Banshee" fullword ascii
    $s2 = "Accentuator" fullword ascii
    $s3 = "menati palpi basava" fullword wide
    $s4 = "aurate" fullword ascii
    $s5 = "Dogger" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "da2bda8fe160d264332564e8f360d4f7" and (all of them)
    ) or (all of them)
}