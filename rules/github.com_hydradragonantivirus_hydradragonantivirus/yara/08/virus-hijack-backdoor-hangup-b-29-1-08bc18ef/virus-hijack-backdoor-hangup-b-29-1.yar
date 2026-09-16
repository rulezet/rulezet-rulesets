rule Virus_Hijack_Backdoor_Hangup_B_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a638c1784e081c782179c7617fe492bb4de7ad3400c388769e5ed6eb2a16dd06"

  strings:
    $s1 = "image::encode_jpeg(Tensor _0, int _1) -> Tensor" fullword ascii
    $s2 = "None, 'n_jobs':" fullword ascii
    $s3 = "@Events@Applications@Microsoft@@QEAA@AEAV?$vector@UGUID_t@Events@Applications@Microsoft@@V?$allocator@UGUID_t@Events@Application" ascii
    $s4 = "@Events@Applications@Microsoft@@QEAA@AEAV?$vector@UGUID_t@Events@Applications@Microsoft@@V?$allocator@UGUID_t@Events@Application" ascii
    $s5 = "es@Events@Applications@Microsoft@@QEAAAEAV0123@V?$initializer_list@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocat" ascii
    $s6 = "es@Events@Applications@Microsoft@@QEAAAEAV0123@V?$initializer_list@U?$pair@$$CBV?$basic_string@DU?$char_traits@D@std@@V?$allocat" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}