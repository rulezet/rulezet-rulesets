rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_e78383c7f2f1_2456 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"
    hash3       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1 = "ion fuck(){return \"GJx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return " ascii
    $s2 = "turn \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s3 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DAa" ascii
    $s4 = "return \"Qh\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(" ascii
    $s5 = "turn \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s6 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Na" ascii
    $s7 = "\"Wo0\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s8 = "uck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}