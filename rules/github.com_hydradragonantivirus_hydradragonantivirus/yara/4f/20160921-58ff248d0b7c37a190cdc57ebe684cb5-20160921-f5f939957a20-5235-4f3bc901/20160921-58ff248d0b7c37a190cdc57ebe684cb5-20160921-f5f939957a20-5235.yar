rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_f5f939957a20_5235 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_f5f939957a207b333a934a05633cece9.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"
    hash3       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "on fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s2 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck()" ascii
    $s3 = "(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s4 = "x\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ot\";})(),(function" ascii
    $s5 = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}