rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_a96b471e778a_2758 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash3       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Sx\";})()," ascii
    $s2 = "rn \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s3 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s4 = "n fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"L" ascii
    $s5 = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Et\";})(),(function fu" ascii
    $s6 = "uck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq" ascii
    $s7 = "\"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}