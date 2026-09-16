rule _20160921_531eaafa1b0a00d86f2203fbd289dd63_20160921_627f79d589bd_5182 {
  meta:
    description = "datamaliciousorder - from files 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash2       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){ret" ascii
    $s2 = "(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3 = "k(){return \"UXf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s4 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retur" ascii
    $s5 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}