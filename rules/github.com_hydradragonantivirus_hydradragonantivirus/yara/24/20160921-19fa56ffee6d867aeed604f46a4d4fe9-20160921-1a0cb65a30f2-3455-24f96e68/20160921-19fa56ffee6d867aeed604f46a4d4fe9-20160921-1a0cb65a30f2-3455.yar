rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_1a0cb65a30f2_3455 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash3       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash4       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash5       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash6       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retu" ascii
    $s2 = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){retu" ascii
    $s3 = "ction fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii
    $s4 = "){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s5 = "turn \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s6 = "rn \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}