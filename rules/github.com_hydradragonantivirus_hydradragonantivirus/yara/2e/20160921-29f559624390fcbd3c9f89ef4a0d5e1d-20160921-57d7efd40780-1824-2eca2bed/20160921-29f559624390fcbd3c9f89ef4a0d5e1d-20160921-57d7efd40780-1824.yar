rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_57d7efd40780_1824 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash3       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"
    hash4       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash5       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1  = "\"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Np\";})(),(funct" ascii
    $s2  = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\";})(),(functio" ascii
    $s3  = "ction fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retur" ascii
    $s4  = "ck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We" ascii
    $s5  = "n \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"YAv\";})(),(fun" ascii
    $s6  = "nction fuck(){return \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s7  = "\"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(func" ascii
    $s8  = "){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";}" ascii
    $s9  = "ck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"GWo" ascii
    $s10 = "k(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}