rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_962ed1e894cd_3457 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js, 20160921_e53844f4bb18305322896332fbd017e8.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash3       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash4       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash5       = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"
    hash6       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"
    hash7       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"
    hash8       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1 = "eturn \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s2 = "uck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc" ascii
    $s3 = "rn \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(fu" ascii
    $s4 = "function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retu" ascii
    $s5 = "h\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function f" ascii
    $s6 = "(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}