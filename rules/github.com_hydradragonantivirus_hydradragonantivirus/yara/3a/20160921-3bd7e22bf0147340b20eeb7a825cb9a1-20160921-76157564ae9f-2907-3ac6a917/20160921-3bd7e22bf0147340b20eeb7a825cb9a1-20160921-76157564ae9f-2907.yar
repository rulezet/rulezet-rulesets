rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_76157564ae9f_2907 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_76157564ae9f7ad7ec97100684b2a5ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s2 = "uck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZL" ascii
    $s3 = "\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s4 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s5 = "),(function fuck(){return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s6 = "){return \"Ot\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"GNm\";})" ascii
    $s7 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Wo\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}