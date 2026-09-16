rule _20160921_04e35734989b05b680234592aacc01ad_20160921_207d0a8168d3_1371 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_5e30fe0c691277f3c6d0814d796ba918.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash3       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash4       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash5       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"

  strings:
    $s1  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retur" ascii
    $s2  = "rn \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s3  = "k(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";}" ascii
    $s4  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"F" ascii
    $s5  = "uck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s6  = "Hj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(functio" ascii
    $s7  = "uck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg" ascii
    $s8  = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){r" ascii
    $s9  = "\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"SUi\";})(),(function " ascii
    $s10 = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai\";})(),(fu" ascii
    $s11 = "turn \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s12 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retur" ascii
    $s13 = "on fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s14 = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}