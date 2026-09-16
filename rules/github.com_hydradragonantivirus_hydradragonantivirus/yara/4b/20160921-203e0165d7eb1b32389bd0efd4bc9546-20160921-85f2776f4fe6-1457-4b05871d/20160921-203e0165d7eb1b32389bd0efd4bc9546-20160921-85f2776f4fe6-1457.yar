rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_85f2776f4fe6_1457 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash3       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"

  strings:
    $s1  = "k(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";}" ascii
    $s2  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"J" ascii
    $s3  = "unction fuck(){return \"Ot\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s4  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DWe" ascii
    $s5  = "nction fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s6  = "ck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";}" ascii
    $s7  = " \"Wo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s8  = "IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Dc\";})(),(functi" ascii
    $s9  = "rn \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MUs\";})(),(f" ascii
    $s10 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ot\";})(),(function fuck" ascii
    $s11 = " fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"ADy" ascii
    $s12 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s13 = ")(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}