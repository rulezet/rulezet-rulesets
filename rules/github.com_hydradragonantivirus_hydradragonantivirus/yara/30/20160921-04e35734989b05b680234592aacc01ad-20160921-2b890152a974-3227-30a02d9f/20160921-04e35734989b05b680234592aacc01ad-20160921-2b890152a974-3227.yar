rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_3227 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash4       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash5       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash6       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retur" ascii
    $s2 = "nction fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){ret" ascii
    $s3 = "){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s4 = "return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MOj\";})()," ascii
    $s5 = "(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";" ascii
    $s6 = "x\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}