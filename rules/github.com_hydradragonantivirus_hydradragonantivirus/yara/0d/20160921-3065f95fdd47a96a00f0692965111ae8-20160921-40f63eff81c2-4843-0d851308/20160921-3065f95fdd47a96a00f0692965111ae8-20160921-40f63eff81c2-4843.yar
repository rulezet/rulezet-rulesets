rule _20160921_3065f95fdd47a96a00f0692965111ae8_20160921_40f63eff81c2_4843 {
  meta:
    description = "datamaliciousorder - from files 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash2       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash3       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash4       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "k(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";" ascii
    $s2 = "unction fuck(){return \"GJx\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){re" ascii
    $s3 = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"DHd\";})(),(func" ascii
    $s4 = "n fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s5 = "n fuck(){return \"XHj\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}