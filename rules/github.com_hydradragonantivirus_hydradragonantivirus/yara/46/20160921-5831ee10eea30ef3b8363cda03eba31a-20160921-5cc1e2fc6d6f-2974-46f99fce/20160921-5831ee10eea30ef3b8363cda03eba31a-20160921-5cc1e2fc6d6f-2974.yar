rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_5cc1e2fc6d6f_2974 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"

  strings:
    $s1 = "k(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\"" ascii
    $s2 = "rn \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s3 = ",(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){" ascii
    $s4 = "fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AU" ascii
    $s5 = "rn \"Ot\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s6 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s7 = "tion fuck(){return \"XHj\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}