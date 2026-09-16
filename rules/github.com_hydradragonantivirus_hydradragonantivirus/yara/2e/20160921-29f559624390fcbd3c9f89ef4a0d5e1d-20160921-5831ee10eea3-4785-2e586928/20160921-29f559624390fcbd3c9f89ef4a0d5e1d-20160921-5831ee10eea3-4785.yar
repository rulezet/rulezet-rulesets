rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_5831ee10eea3_4785 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_962ed1e894cd91f421ad984310ce3140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash3       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash4       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"

  strings:
    $s1 = "turn \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s2 = "n \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3 = " fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"O" ascii
    $s4 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(" ascii
    $s5 = "(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}