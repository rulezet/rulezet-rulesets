rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_7f6803f2f6f6_4193 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash3       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash4       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1 = "),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(" ascii
    $s2 = " \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s3 = "return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})" ascii
    $s4 = " \"Pc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s5 = "n \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}