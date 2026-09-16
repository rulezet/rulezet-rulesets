import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_94847_234_1_Virus_Hijack_Gen_T_191 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.94847_234_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_7.vir, Virus.Hijack_Trojan.Agent.DQQO_215.vir, Virus.Hijack_Trojan.Agent.DQQO_344.vir, Virus.Hijack_Trojan.Agent.DQQO_50.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b2e35dd23203c7f75e720f86ecc40f61a9ab1db0ee1f4f70a2979aa6c0d5e2a"
    hash2       = "8dd6cef8efe1855ae786a5f8420cd8dcf8884eabcedffbfaa723eff340e82d3c"
    hash3       = "304cd8dbc33471a59465d359f2ab8353a574edaf84281e35552ac6e2a77a5a3e"
    hash4       = "77fc057ae0ceb636165fb26cdcb4c9e20121583759e55d1fd3554397dd085077"
    hash5       = "a2fd90c44dcc8b5dd44332c955605cfe1465960c0d4202a292c9f7e3786a1a7f"
    hash6       = "be42ad996d3550051c1f909b56fa10793b9a4e502af03c3872d892d339630de1"
    hash7       = "f804a53430512a8089fbaf3212c298acf00da3248d46132b8259c12b09b38979"
    hash8       = "1f6ac25665b00312be6a0868a80bb38a2d76f4c51d68fa3afb3753c1401ab4e2"
    hash9       = "610fd56db32486adc7094b20e2f4c1ae3b557c97f107e56508b3e383a362bc0e"
    hash10      = "3933482b2ac2c471078585980b6da5d1a489a94799c9e270f917b478e6453d71"
    hash11      = "a2ed48add31a53a5bd984fbab960264adb7b4910727d6d30be0b3ca0f9449abc"
    hash12      = "5a4e2c5e991b9e68dff9539f16c2aabbc8721a658b1765448364254278dc9b79"

  strings:
    $s1  = "?T2_EVENT_REDO_EXECUTED@Data@Lift@@3V?$ValuePointDefinition@X@12@B" fullword ascii
    $s2  = "?T2_EVENT_UNDO_EXECUTED@Data@Lift@@3V?$ValuePointDefinition@X@12@B" fullword ascii
    $s3  = "?T2_SMART_SELECT_START@Data@Lift@@3V?$ValuePointDefinition@W4CommandTriggerType@Telemetry@@@12@B" fullword ascii
    $s4  = "?GetSharedMemory@Lift@@YAPAXIIAA_N@Z" fullword ascii
    $s5  = "?GetCorrelationVector@TelemetryProvider@Telemetry@Lift@@QAEAAVCorrelationVector@23@XZ" fullword ascii
    $s6  = "?GetGlobalInstance@TelemetryProvider@Telemetry@Lift@@SAPAV123@XZ" fullword ascii
    $s7  = "?T2_STORE_RATING_PROMPT_OUTCOME_START@Data@Lift@@3V?$ValuePointDefinition@X@12@B" fullword ascii
    $s8  = "?T2_PUBLISH_ESTIMATE_UNCOMPRESSED_BXF_SIZE_BYTES@Data@Lift@@3V?$ValuePointDefinition@I@12@B" fullword ascii
    $s9  = "?T2_STORE_RATING_PROMPT_OUTCOME_RATE_SELECTED@Data@Lift@@3V?$ValuePointDefinition@_N@12@B" fullword ascii
    $s10 = "?T2_APP_STATE_COMMUNITY_DISCOVER_PAGE_SHOWN@Data@Lift@@3V?$GlobalValuePointDefinition@_N@12@B" fullword ascii
    $s11 = "?T2_STORE_RATING_PROMPT_OUTCOME_END@Data@Lift@@3V?$ValuePointDefinition@W4ActivityResult@Telemetry@@@12@B" fullword ascii
    $s12 = "?T2_APP_STATE_TOTAL_COMMUNITY_ENABLED@Data@Lift@@3V?$GlobalValuePointDefinition@H@12@B" fullword ascii
    $s13 = "?T2_PUBLISH_UPLOAD_SIZE_BYTES@Data@Lift@@3V?$ValuePointDefinition@I@12@B" fullword ascii
    $s14 = "?T2_GLOBAL_COMMUNITY_USER_ID@Data@Lift@@3V?$GlobalValuePointDefinition@V?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@" ascii
    $s15 = "?T2_GLOBAL_COMMUNITY_USER_ID@Data@Lift@@3V?$GlobalValuePointDefinition@V?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@" ascii
    $s16 = "?Increment@CorrelationVector@Telemetry@Lift@@QAEXXZ" fullword ascii
    $s17 = "?T2_APP_STATE_TOP_BAR_EXTENDED@Data@Lift@@3V?$GlobalValuePointDefinition@_N@12@B" fullword ascii
    $s18 = "?T2_CREATION_OPEN_FILESIZE@Data@Lift@@3V?$ValuePointDefinition@I@12@B" fullword ascii
    $s19 = "?Extend@CorrelationVector@Telemetry@Lift@@QAEXXZ" fullword ascii
    $s20 = "?T2_GENERIC_EDMHRESULT@Data@Lift@@3V?$ValuePointDefinition@H@12@B" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26babd76bbb7f9c516a338b0601b4c9f" and (8 of them)
    ) or (all of them)
}