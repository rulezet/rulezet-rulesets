rule _20160921_1e07803d7c44ae0b61b5ddf189c80675_20160921_460a913db46b_76 {
  meta:
    description = "datamaliciousorder - from files 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_460a913db46b41c41035cc210ed5fba0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash2       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"

  strings:
    $s1  = "k(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"PDf\";" ascii
    $s2  = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ai\";})(),(function fuc" ascii
    $s3  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuc" ascii
    $s4  = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ug\";})()," ascii
    $s5  = ")(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"PDf\";})(),(function fuc" ascii
    $s6  = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s7  = "rn \"Ar\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s8  = "function fuck(){return \"DAa\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){r" ascii
    $s9  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){r" ascii
    $s10 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck()" ascii
    $s11 = "eturn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})()" ascii
    $s12 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s13 = "ction fuck(){return \"AUx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s14 = "turn \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(" ascii
    $s15 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s16 = "uck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"ZV" ascii
    $s17 = "})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Hs\";})(),(function fuck" ascii
    $s18 = "urn \"Mw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"CCb\";})(),(" ascii
    $s19 = "eturn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s20 = "),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}