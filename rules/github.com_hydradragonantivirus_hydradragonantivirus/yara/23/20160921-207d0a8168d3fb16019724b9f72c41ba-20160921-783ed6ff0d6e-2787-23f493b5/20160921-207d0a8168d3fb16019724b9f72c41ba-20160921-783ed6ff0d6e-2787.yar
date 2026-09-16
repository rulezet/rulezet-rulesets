rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_783ed6ff0d6e_2787 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"

  strings:
    $s1 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){r" ascii
    $s2 = "tion fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii
    $s3 = "Jx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s4 = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5 = "return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})()" ascii
    $s6 = "{return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s7 = "){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}