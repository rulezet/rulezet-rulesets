rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_52ab3697b827_5024 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash3       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash4       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"

  strings:
    $s1 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv" ascii
    $s2 = "(){return \"Wo0\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s3 = "unction fuck(){return \"Qh\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s4 = "tion fuck(){return \"Nm\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return " ascii
    $s5 = ")(),(function fuck(){return \"Et\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Np\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}