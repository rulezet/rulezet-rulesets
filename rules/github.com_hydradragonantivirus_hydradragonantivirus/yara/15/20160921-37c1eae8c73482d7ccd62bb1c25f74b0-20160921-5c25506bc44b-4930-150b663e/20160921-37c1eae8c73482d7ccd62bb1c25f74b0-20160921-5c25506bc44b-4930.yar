rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_5c25506bc44b_4930 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"

  strings:
    $s1 = "ck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";" ascii
    $s2 = "ck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\"" ascii
    $s3 = "){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})" ascii
    $s4 = "Xf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(functio" ascii
    $s5 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}