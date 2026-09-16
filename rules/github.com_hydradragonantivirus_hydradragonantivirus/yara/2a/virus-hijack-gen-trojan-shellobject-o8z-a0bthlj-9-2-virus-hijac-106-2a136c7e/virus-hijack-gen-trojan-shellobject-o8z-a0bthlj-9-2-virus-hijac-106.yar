rule _Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a0BtHLj_9_2_Virus_Hijac_106 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a0BtHLj_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aO1tmfb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aO1tmfb_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aO1tmfb_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aOU94xe_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_7.vir, Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98.vir, Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98_1.vir, Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98_2.vir, Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98_3.vir, Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98_4.vir, Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98_5.vir, Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.98_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c02afeca4178e6ba8be0d29fc4717801486ee74a35e41aa8c8dc4e5e031d5aed"
    hash2       = "267100ded85a6f42103d5a66b9cab10ca20e8c146eb8fb5bfa1511fed4e11133"
    hash3       = "583055b2b07102cafad993be302926c63a6c57cf48d4ba87bffa1120a627c870"
    hash4       = "0166389e4cf033093f3d2d19a12cf3b0dff6442f4ef3fb30c295748d93313044"
    hash5       = "c515f7bf40d2e5ac2215a06ae5e79304e1db117cd85e176b530894870691f929"
    hash6       = "88c01558c0aabd899e25652b7b0e181fa3a1a578884037d0f80d0006016e4abf"
    hash7       = "19ea5bdd4feae6b82d7811781c5706fa4e3733d6c22478ac0f21b5f2c915ed54"
    hash8       = "db5ee966a1db35e93175677ee199428c45898aa0781b0c8df91dad04cd01c280"
    hash9       = "cf6140ec718933b2150498dbb11ca18218e0f7bb8cf22a772de2d9fe397e9946"
    hash10      = "dd3316cd4e2f97dd37fbd09ee84eb6f26fdb6b4b9d33296f1a47bc7247781472"
    hash11      = "b2b0e58104ee4fa6a0b18be69a4fab08e13d6dbaf5a933dee704a8730a73ad75"
    hash12      = "22187aa8e0b6f1e4a7a205238e907d3200e4686b98ce160dd9266f7b7dca16e9"
    hash13      = "6263d707f42e65e9cf57b9341161307841f32e6bc29f6fb85d916b443359def7"
    hash14      = "f43e0dc51238b959035c76f7cc39d718b09247d603948c7a2d28aedc77d36c83"
    hash15      = "69751692fd56a00548e63c05782fc4df07fc75e9e144359b51e84d3060473284"
    hash16      = "d18bb089359c14be15af5377a963c708146cc00fd041c3a2cf1c299b74fd9808"
    hash17      = "5e1be525a0fcc5418c1257fb0b7d4f8b80f25f1c069d2a853273e0543dc17b4c"
    hash18      = "6487299186bd1161873d43bb1a26aa86f18421937dce891f2d49847389f53223"
    hash19      = "2f4401003133461218adc588eff5f714b8e2d346202395bd013eac292136e2e3"
    hash20      = "df4573ea161f4817c1a0f740fa3ed1157c6d6e1b5322de25c0fa015859ba7472"
    hash21      = "16864ab3c474f3260d66be2fbeee90dfd77807f5ba4dd2929fe38292686f3522"
    hash22      = "8db5f7eda33ea82c2390098b322116be61abc76d9a65daa958e6a3fed84313b4"
    hash23      = "7f5c33c55c0521c5f1131eebf821ed2f101442adc2e7a87226c3b1bb44701e1a"
    hash24      = "33f614a8668bf39d4879d8d8c01f5b904f7899aa3447488009e3da466474405f"
    hash25      = "52c4efb40dd9f8aed003f2ea312fe1e34d646ac72a121a5dae95c0d2202adb8b"

  strings:
    $s1  = "Failed to create mutex - aborting" fullword ascii
    $s2  = "** Hey, GetLastError() == %d (before read). <------" fullword ascii
    $s3  = "*** Forced trickler.inf download failure! ***" fullword ascii
    $s4  = "** Hey, GetLastError() returned %d again. <------" fullword ascii
    $s5  = "*** CxSocket Read Loop Complete, %d of %d bytes ***" fullword ascii
    $s6  = "POST http://%s:%d%s HTTP/%s" fullword ascii
    $s7  = "******* InternetReadFile() loop complete, %d bytes total" fullword ascii
    $s8  = "*** Forced data-file download failure! ***" fullword ascii
    $s9  = "*** Forced data-file checkinfo download failure! ***" fullword ascii
    $s10 = "*** Forced update download failure! ***" fullword ascii
    $s11 = "HTTP start: %s:%d %s %s ---------- start ---------" fullword ascii
    $s12 = "HTTP done: %s:%d %s %s ----- end ----- returned %d, %d bytes, in %d ms (%s)" fullword ascii
    $s13 = "*** CxSocket Read() got %d bytes, %s ***" fullword ascii
    $s14 = "******* InternetReadFile received %d bytes, %d total" fullword ascii
    $s15 = "******* HttpQueryInfo(CONNECTION) ********" fullword ascii
    $s16 = "******* InternetReadFile() returned failure, error or timeout ********" fullword ascii
    $s17 = "** Handle: httpSession = %08X" fullword ascii
    $s18 = "GExeBind_UnbindAll: no open target" fullword ascii
    $s19 = "GExeBind_UnbindAll: target empty" fullword ascii
    $s20 = "GExeBind_BindStringData: target, tag and/or data empty" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}