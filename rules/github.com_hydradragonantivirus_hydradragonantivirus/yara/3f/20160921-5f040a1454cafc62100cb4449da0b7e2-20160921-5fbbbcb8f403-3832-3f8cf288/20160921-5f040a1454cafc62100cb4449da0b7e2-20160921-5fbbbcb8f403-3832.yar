rule _20160921_5f040a1454cafc62100cb4449da0b7e2_20160921_5fbbbcb8f403_3832 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_c779962dc8b38bbb280b695e631131fa.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash2       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash3       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash4       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash5       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"
    hash6       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "Kv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function" ascii
    $s2 = "{return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";}" ascii
    $s3 = "ck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";" ascii
    $s4 = " \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(func" ascii
    $s5 = "fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn" ascii
    $s6 = "(function fuck(){return \"DHd\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}