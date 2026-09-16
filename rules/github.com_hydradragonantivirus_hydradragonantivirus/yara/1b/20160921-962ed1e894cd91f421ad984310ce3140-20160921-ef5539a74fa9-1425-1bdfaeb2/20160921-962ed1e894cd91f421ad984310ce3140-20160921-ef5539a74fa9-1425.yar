rule _20160921_962ed1e894cd91f421ad984310ce3140_20160921_ef5539a74fa9_1425 {
  meta:
    description = "datamaliciousorder - from files 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1  = " fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"M" ascii
    $s2  = "k(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\"" ascii
    $s3  = "fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"G" ascii
    $s4  = "ck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";" ascii
    $s5  = "e\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s6  = "eturn \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})()" ascii
    $s7  = "uck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn" ascii
    $s8  = "n \"TTs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s9  = "AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s10 = "){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";}" ascii
    $s11 = "ck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s12 = "})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s13 = "(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){r" ascii
    $s14 = " fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}