rule _Virus_Hijack_Gen_Trojan_ShellObject_dyX_ai9jxwp_1_1_Virus_Hijac_167 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dyX@ai9jxwp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a98a2728de2eea7db2532bbf8f79c6ec1dc6a120fe07103807b03434acedd84"
    hash2       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash3       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash4       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash5       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash6       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash7       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"
    hash8       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash9       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash10      = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash11      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash12      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"

  strings:
    $s1  = "%s: Fatal Error - Trying to bring up spinner for unsupported API's" fullword ascii
    $s2  = "%s: invoked clientScope: %s data?: %s workflow?: %s" fullword ascii
    $s3  = "%s: invoked clientId: %s clientScope: %s data?: %s workflow?: %s" fullword ascii
    $s4  = "%s: invoked with Passed locales list as %s" fullword ascii
    $s5  = "%s: Error creating jump url for entry URL: %s, client Id: %s, scope: %s" fullword ascii
    $s6  = "%s: Failed with errorcode (%d)" fullword ascii
    $s7  = "%s: invoked with state %d" fullword ascii
    $s8  = "%s: Update refresh interval to %d " fullword ascii
    $s9  = "%s: Saving Auth synchronously %d" fullword ascii
    $s10 = "%s: checking if device token is invalidated" fullword ascii
    $s11 = "%s: Using unauth entry url: %s" fullword ascii
    $s12 = "%s: Reordered locales list is identical to passed locales as no installed locales were found." fullword ascii
    $s13 = "%s: Reordered locales list is empty as no locales were passed." fullword ascii
    $s14 = "Trying to bring up spinner for unsupported API's" fullword ascii
    $s15 = "%s: Reordered List contains %s" fullword ascii
    $s16 = "%s: request id: %lu api: %d call-status: %d profile-status: %d workflow?: %s spinner?: %s" fullword ascii
    $s17 = "Spinner." fullword ascii
    $s18 = "%s: Received vulcan notification %d" fullword ascii
    $s19 = "%s: Received vulcan notification but not modification found in file" fullword ascii
    $s20 = "$$$/ngl/mainmenu/help/manage_account=Manage My Account..." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}