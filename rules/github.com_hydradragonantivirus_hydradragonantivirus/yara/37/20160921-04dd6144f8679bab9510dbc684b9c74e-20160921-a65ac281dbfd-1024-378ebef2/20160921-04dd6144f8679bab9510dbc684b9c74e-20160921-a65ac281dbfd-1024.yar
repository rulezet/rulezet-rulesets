rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_a65ac281dbfd_1024 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash3       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash4       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1  = "urn \"Mt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(" ascii
    $s2  = "(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw\";}" ascii
    $s3  = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s4  = "on f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return " ascii
    $s5  = "00(){return \"KDh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"MDb" ascii
    $s6  = "b\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function " ascii
    $s7  = "function f000(){return \"Yv\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s8  = "0(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YTp" ascii
    $s9  = ")(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"UEg\";})(),(function f000" ascii
    $s10 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"YTp\";" ascii
    $s11 = "nction f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Wb\";})(),(function f000(){retu" ascii
    $s12 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii
    $s13 = "{return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";}" ascii
    $s14 = " f000(){return \"Rh\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SE" ascii
    $s15 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f" ascii
    $s16 = "b\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s17 = "ction f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BMj\";})(),(function f000(){retu" ascii
    $s18 = "ZFe\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}