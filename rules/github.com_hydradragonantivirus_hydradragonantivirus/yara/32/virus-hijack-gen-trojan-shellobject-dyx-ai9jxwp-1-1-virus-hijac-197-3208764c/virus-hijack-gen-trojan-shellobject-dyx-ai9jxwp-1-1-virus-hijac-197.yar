rule _Virus_Hijack_Gen_Trojan_ShellObject_dyX_ai9jxwp_1_1_Virus_Hijac_197 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dyX@ai9jxwp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a98a2728de2eea7db2532bbf8f79c6ec1dc6a120fe07103807b03434acedd84"
    hash2       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash3       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash4       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash5       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash6       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash7       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash8       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash9       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash10      = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"
    hash11      = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash12      = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash13      = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash14      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash15      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"

  strings:
    $s1  = "User / Password  NOT present" fullword ascii
    $s2  = "DistNGL Integ ADC-4248130 : ProcessCachedNglProfile return good profile, no need to run workflows" fullword ascii
    $s3  = "DistNGL Integ ADC-4248130: ********  Starting new session ********" fullword ascii
    $s4  = "DistNGL Integ ADC-4248130: Processed profile for Acrotray... " fullword ascii
    $s5  = "AcroNGL Integ ADC-4240758 : AcroNGLProfileManager Processing NGL Profile..." fullword ascii
    $s6  = "  Operating Mode  : " fullword ascii
    $s7  = "DistNGL Integ ADC-4248130:    workflowCompleteNotifier... No workflow to process" fullword ascii
    $s8  = "Entitlement is Reader/Residue." fullword ascii
    $s9  = "DistNGL Integ ADC-4248130: == printAMTData Result ErrorCode : [%ld]" fullword ascii
    $s10 = "DistNGL Integ ADC-4248130: == printProfileData Profile ErrorCode : [%ld]" fullword ascii
    $s11 = "abort:://ignore_wf?retry_request=false" fullword ascii
    $s12 = "Entitlement is Basic." fullword ascii
    $s13 = "Entitlement is Acrobat Professional." fullword ascii
    $s14 = "  Refresh Interval : " fullword ascii
    $s15 = "DistNGL Integ ADC-4248130: HandleWorkflow starting ::: " fullword ascii
    $s16 = "  Device ID : " fullword ascii
    $s17 = "DistNGL Integ ADC-4248130: Starting NGL in DISTILLER" fullword ascii
    $s18 = "DistNGL Integ ADC-4248130: undefined workflow" fullword ascii
    $s19 = "DistNGL Integ ADC-4248130: InitializeProfileUpdates With SuppressedUI" fullword ascii
    $s20 = "  App Profile : " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}