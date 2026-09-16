rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_17ed90b369ab_4199 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash3       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash4       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq" ascii
    $s2 = " \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s3 = "function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){re" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(func" ascii
    $s5 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}