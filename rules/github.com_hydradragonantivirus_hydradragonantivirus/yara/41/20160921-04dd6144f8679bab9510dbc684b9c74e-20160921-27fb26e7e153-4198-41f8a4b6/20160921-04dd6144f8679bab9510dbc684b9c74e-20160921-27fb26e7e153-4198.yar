rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_27fb26e7e153_4198 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_cff7808833d9e819d4a4f10450848a81.js, 20160921_e1835bc92c4604db194bc49df621cade.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"
    hash4       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash5       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash6       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "function f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){ret" ascii
    $s2 = "){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s3 = "f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv" ascii
    $s4 = "){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})()" ascii
    $s5 = "turn \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}