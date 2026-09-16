rule _20160921_bd6b4f506f527835a48516850a16c1a6_20160921_db727bb0ba7a_4044 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = "(function fuck(){return \"Ve\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s2 = "uck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq" ascii
    $s3 = "ck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"GNm" ascii
    $s4 = "nction fuck(){return \"EHo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5 = "){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})" ascii
    $s6 = "uck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}