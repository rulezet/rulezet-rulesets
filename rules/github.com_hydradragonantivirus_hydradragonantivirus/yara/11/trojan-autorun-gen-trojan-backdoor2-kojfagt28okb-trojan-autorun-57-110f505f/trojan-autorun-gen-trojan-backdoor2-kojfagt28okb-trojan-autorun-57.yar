rule _Trojan_Autorun_Gen_Trojan_Backdoor2_koJfaGT28okb_Trojan_Autorun_57 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Trojan.Backdoor2.koJfaGT28okb.vir, Trojan.Autorun_Gen.Trojan.Backdoor2.noZbaKq9kbjb.vir, Trojan.Autorun_Gen.Trojan.Backdoor2.toZbaaK8fvob.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_132_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_150_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amB8wPo_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.kAZ@aCEmdoo_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71ba9050839ee1fe4b444e16d8beeeaeff6e81865cd5759446263e9a4a860cba"
    hash2       = "a7a37735eadf11931d27da28cbd3b7af132be6300f40a4b6e5cd3afb9e298d6f"
    hash3       = "02e57325bcdca7a87e02318ccd5eb858885ae852920fee22c524ba8a7825de6a"
    hash4       = "026b648082d80f195ae96c69c8d62aff88631359c82dad1316628d3d08dd580f"
    hash5       = "b9938757b55a50ab051340b0a506d4d1d783de182c2ad24e28357b0f5df39844"
    hash6       = "a95bec0faebade2c5abb839d9eada9332584d035b69a84b092ecb7bb448b8118"
    hash7       = "9666562abaa5501197e5e4bbbd70ce66adbef702588b8df8fa60e011468fb33e"
    hash8       = "5242bcb67ba42a7b94093e55d09ada5babd5a8d6042f5265a309d3fcb018a98a"
    hash9       = "6146fd9df4d4c2aacc21a8e0144c57a6b3567dc072ce2de88f831d61f3a66aa6"

  strings:
    $s1  = "@@@buffered_integration_shell_notifier_impl@Integration@AppV@@AEAAXAEBV?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifie" ascii
    $s2  = ".?AV?$_Ref_count@V?$ManagingAuthorityLegacyT@Uempty@?A0x84c360c3@ManagingAuthority@Integration@AppV@@@ManagingAuthority@Integrat" ascii
    $s3  = "tegration_shell_notifier_impl@Integration@AppV@@AEAAXAEBV?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifier@Integration@" ascii
    $s4  = "_W@2@@2@@std@@@buffered_integration_shell_notifier_impl@Integration@AppV@@AEAAXAEBV?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_s" ascii
    $s5  = "@buffered_integration_shell_notifier_impl@Integration@AppV@@AEAAXAEBV?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifier@" ascii
    $s6  = ".?AV?$scope_guard_func_impl@V?$_Bind@$00JQ6AJPEAUHKEY__@@@ZAEAPEAU1@@std@@@utility@appv@@" fullword ascii
    $s7  = ".?AV?$scope_guard_func_impl@V?$_Bind@$00XU?$_Pmf_wrap@P8PublishPackageLink@Integration@AppV@@EAAXXZXV123@$$$V@std@@AEAV?$shared_" ascii
    $s8  = ".?AV?$scope_guard_func_impl@V?$_Bind@$00XU?$_Pmf_wrap@P8PublishPackageLink@Integration@AppV@@EAAXXZXV123@$$$V@std@@AEAV?$shared_" ascii
    $s9  = "dIntegration status store failed to create registry key for the store with error: '%1%'" fullword wide
    $s10 = ".?AVnotification_task_impl@?1???$queue_function@V?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifier@Integration@AppV@@EA" ascii
    $s11 = ".?AV?$_Bind@$00XU?$_Pmf_wrap@P8unregister_command@@EAAXAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@ZXV1" ascii
    $s12 = ".?AV?$_Func_impl@U?$_Callable_obj@V?$_Bind@$00XU?$_Pmf_wrap@P8unregister_command@@EAAXAEBV?$basic_string@_WU?$char_traits@_W@std" ascii
    $s13 = ".?AV?$_Ref_count@Vnotification_task_impl@?1???$queue_function@V?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifier@Integr" ascii
    $s14 = ".?AVnotification_task_impl@?1???$queue_function@V?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifier@Integration@AppV@@EA" ascii
    $s15 = ".?AV?$_Bind@$00XU?$_Pmf_wrap@P8unregister_command@@EAAXAEBV?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@@ZXV1" ascii
    $s16 = "@@V?$allocator@_W@2@@std@@@ZXV1@AEBV23@@std@@QEAVunregister_command@@AEAV?$_Ph@$00@2@@std@@$0A@@std@@V?$allocator@V?$_Func_class" ascii
    $s17 = ".?AVnotification_task_impl@?1???$queue_function@V?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifier@Integration@AppV@@EA" ascii
    $s18 = ".?AV?$_Ref_count@Vnotification_task_impl@?1???$queue_function@V?$_Bind@$0A@XV?$_Mem_fn_wrap@XP8integration_shell_notifier@Integr" ascii
    $s19 = ".?AV?$_Ref_count@V?$ManagingAuthorityLegacyT@Uempty@?A0x84c360c3@ManagingAuthority@Integration@AppV@@@ManagingAuthority@Integrat" ascii
    $s20 = ".?AUempty@?A0x84c360c3@ManagingAuthority@Integration@AppV@@" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}