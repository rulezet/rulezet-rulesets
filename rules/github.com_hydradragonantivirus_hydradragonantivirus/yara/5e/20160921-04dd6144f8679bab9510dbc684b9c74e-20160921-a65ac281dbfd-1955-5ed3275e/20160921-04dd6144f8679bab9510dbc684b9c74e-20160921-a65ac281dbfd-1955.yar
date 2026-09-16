rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_a65ac281dbfd_1955 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_e432cba10cde369693d6b125dda112c7.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash3       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"
    hash4       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash5       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "nction f000(){return \"Sq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii
    $s2 = "rn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3 = " \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(funct" ascii
    $s4 = ";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f0" ascii
    $s5 = " f000(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"H" ascii
    $s6 = "(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";" ascii
    $s7 = "),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s8 = "return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";})(" ascii
    $s9 = "on f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}