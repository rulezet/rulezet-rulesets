rule _20160921_7dec24f022af3c1ffe46748172dd6cad_20160921_ad0fbcfca87e_5445 {
  meta:
    description = "datamaliciousorder - from files 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_e07d4e2b80172d933515ba35e18c07eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash2       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash3       = "d93efcba4ba3ef570f21adda2cc5413ab9ed3865a53a97ad1e05113ebc7c4787"

  strings:
    $s1 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0" ascii
    $s2 = "Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function " ascii
    $s3 = " \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(func" ascii
    $s4 = "ction fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s5 = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}