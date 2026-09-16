rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_7caba45960de_630 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_7caba45960de8ab0904dc3a8514f2614.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"
    hash3       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1  = "return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s2  = "uck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TT" ascii
    $s3  = "(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){re" ascii
    $s4  = "e\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii
    $s5  = "ck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\"" ascii
    $s6  = ";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function f" ascii
    $s7  = " fuck(){return \"XFd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s8  = "),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(" ascii
    $s9  = "n fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"D" ascii
    $s10 = "){return \"XFd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";" ascii
    $s11 = "rn \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(" ascii
    $s12 = "k(){return \"XFd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\"" ascii
    $s13 = "Kq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function" ascii
    $s14 = "function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){ret" ascii
    $s15 = "k(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs" ascii
    $s16 = "unction fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retu" ascii
    $s17 = ",(function fuck(){return \"XFd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck()" ascii
    $s18 = "ction fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return" ascii
    $s19 = ";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuc" ascii
    $s20 = "n fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}