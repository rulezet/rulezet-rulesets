rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_b1a0d856c15e_4931 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"

  strings:
    $s1 = " \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s2 = "turn \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s3 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"PDf\";})(),(function " ascii
    $s4 = "return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(" ascii
    $s5 = "(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}