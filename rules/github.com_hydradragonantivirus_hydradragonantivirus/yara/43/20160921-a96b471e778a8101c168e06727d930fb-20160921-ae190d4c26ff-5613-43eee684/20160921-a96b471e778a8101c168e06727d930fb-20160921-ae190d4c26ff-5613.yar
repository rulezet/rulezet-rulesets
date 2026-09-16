rule _20160921_a96b471e778a8101c168e06727d930fb_20160921_ae190d4c26ff_5613 {
  meta:
    description = "datamaliciousorder - from files 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"

  strings:
    $s1 = "k(){return \"Hs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MOj\";" ascii
    $s2 = ")(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s3 = "IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s4 = "){return \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii
    $s5 = "turn \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}