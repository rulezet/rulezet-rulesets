rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_a96b471e778a_3735 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1 = "unction fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){re" ascii
    $s2 = "uck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQ" ascii
    $s3 = "),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})(),(function fuck()" ascii
    $s4 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii
    $s5 = "(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){re" ascii
    $s6 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}