rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_6c49e33f1abb_1671 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"

  strings:
    $s1  = "urn \"DAa\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s2  = "uck(){return \"FJs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DHd" ascii
    $s3  = " \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s4  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return " ascii
    $s5  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck()" ascii
    $s6  = "(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";}" ascii
    $s7  = "ion fuck(){return \"Yk\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return " ascii
    $s8  = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return " ascii
    $s9  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s10 = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Sx\";}" ascii
    $s11 = "uck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}