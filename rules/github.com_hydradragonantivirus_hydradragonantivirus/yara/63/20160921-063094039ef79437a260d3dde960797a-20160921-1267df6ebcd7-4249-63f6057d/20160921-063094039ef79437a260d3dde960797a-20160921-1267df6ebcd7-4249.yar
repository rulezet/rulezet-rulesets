rule _20160921_063094039ef79437a260d3dde960797a_20160921_1267df6ebcd7_4249 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash3       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash4       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";}" ascii
    $s2 = " fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s3 = "{return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s4 = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s5 = "ck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}