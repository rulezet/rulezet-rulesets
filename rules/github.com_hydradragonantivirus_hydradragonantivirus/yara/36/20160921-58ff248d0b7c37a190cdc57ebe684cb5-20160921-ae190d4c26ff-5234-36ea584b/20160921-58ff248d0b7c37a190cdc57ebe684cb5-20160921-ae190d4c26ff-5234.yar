rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_ae190d4c26ff_5234 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash3       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1 = "{return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";}" ascii
    $s2 = "urn \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s3 = "rn \"CTm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(f" ascii
    $s4 = "fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"U" ascii
    $s5 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}