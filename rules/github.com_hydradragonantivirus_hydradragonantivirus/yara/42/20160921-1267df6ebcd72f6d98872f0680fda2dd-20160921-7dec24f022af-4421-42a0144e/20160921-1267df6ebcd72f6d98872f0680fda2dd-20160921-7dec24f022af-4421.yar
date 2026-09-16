rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_7dec24f022af_4421 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash3       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash4       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s2 = " fuck(){return \"ZWu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IP" ascii
    $s3 = " \"Jh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(func" ascii
    $s4 = ",(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){r" ascii
    $s5 = " \"MIl\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}