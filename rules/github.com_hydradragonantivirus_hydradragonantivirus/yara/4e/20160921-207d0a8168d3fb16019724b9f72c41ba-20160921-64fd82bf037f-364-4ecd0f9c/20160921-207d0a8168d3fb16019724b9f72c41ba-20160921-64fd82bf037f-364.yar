rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_64fd82bf037f_364 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash3       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash4       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash5       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash6       = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"
    hash7       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"
    hash8       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1  = "rn \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2  = ";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Mw\";})(),(function fuck" ascii
    $s3  = "return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s4  = "(function fuck(){return \"GJx\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){r" ascii
    $s5  = "ion fuck(){return \"XHj\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s6  = "{return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(" ascii
    $s7  = "(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"USf\";})(),(function fuck(" ascii
    $s8  = "g\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s9  = "k(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"VMi\"" ascii
    $s10 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return " ascii
    $s11 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s12 = "PDf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s13 = "XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function" ascii
    $s14 = ";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s15 = "{return \"MIl\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})" ascii
    $s16 = "),(function fuck(){return \"Na\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s17 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retur" ascii
    $s18 = " fuck(){return \"CCb\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"" ascii
    $s19 = "n \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"YAv\";})(),(fu" ascii
    $s20 = " fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Mw" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}