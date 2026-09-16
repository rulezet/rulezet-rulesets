rule _20160921_7dec24f022af3c1ffe46748172dd6cad_20160921_f5230fc58405_1902 {
  meta:
    description = "datamaliciousorder - from files 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash2       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1  = "n fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"H" ascii
    $s2  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){" ascii
    $s3  = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s4  = "tion fuck(){return \"EHo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return " ascii
    $s5  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Xg" ascii
    $s6  = ",(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){r" ascii
    $s7  = "})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xg\";})(),(function fuck" ascii
    $s8  = "k(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\"" ascii
    $s9  = "n fuck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg" ascii
    $s10 = "\"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}