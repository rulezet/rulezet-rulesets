import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_9_1_Virus_Hijac_521 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.mvZ@amBwvTb_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8178aa730e044365fcc4665f1bc4ffcf682d25cbb4e268cbdfd1e02a59e3a7b"
    hash2       = "6f2ea01918463d6c86c8675a48274811e2b0e3d6c4eff1cdddf8c0db301e8f4a"
    hash3       = "37365d2413fcc790064f20fb64b5793d0c17165ac5facf2fff4046de2c30059c"

  strings:
    $s1 = "XXZ@QBE@V12@@Z@@detail@boost@@@detail@boost@@" fullword ascii
    $s2 = "ture@X@2@@Z@QBE@0@Z@@detail@boost@@" fullword ascii
    $s3 = "tail@boost@@@detail@boost@@" fullword ascii
    $s4 = "@_K@2@@Z@QBE@V?$future@Vwamp_call_result@autobahn@@@2@@Z@@detail@boost@@@detail@boost@@" fullword ascii
    $s5 = "e@Vwamp_call_result@autobahn@@@2@@Z@@detail@boost@@" fullword ascii
    $s6 = "g@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@Z@@detail@boost@@" fullword ascii
    $s7 = "future@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@Z@@detail@boost@@@detail@boost@@" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "47d186778bc9d198554e460e0d3becb7" and (all of them)
    ) or (all of them)
}