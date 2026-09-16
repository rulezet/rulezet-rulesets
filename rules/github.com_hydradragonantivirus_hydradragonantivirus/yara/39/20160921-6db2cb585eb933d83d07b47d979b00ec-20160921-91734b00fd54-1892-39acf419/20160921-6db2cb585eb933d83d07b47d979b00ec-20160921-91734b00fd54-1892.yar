rule _20160921_6db2cb585eb933d83d07b47d979b00ec_20160921_91734b00fd54_1892 {
  meta:
    description = "datamaliciousorder - from files 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash2       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"

  strings:
    $s1  = " fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"B" ascii
    $s2  = "on fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s3  = "\"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(funct" ascii
    $s4  = "unction fuck(){return \"Pc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s5  = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s6  = "n fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"I" ascii
    $s7  = "uck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn" ascii
    $s8  = "){return \"Ai\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})" ascii
    $s9  = "n fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Pc" ascii
    $s10 = " fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"V" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}