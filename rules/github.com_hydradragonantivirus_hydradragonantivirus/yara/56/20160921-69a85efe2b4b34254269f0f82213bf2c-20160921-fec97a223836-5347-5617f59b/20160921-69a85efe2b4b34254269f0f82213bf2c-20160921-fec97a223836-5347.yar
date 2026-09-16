rule _20160921_69a85efe2b4b34254269f0f82213bf2c_20160921_fec97a223836_5347 {
  meta:
    description = "datamaliciousorder - from files 20160921_69a85efe2b4b34254269f0f82213bf2c.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck" ascii
    $s2 = "tion fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s3 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){re" ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";" ascii
    $s5 = "),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}