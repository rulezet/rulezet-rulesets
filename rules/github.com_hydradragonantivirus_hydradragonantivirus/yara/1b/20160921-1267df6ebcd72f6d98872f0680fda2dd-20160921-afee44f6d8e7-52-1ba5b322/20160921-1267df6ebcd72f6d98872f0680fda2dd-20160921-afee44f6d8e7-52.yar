rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_afee44f6d8e7_52 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash3       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1  = "k(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";" ascii
    $s2  = ",(function fuck(){return \"AUx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s3  = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s4  = "fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"U" ascii
    $s5  = "rn \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s6  = "s\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function" ascii
    $s7  = "\"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(fun" ascii
    $s8  = "MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"TTs\";})(),(functi" ascii
    $s9  = "CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(functi" ascii
    $s10 = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(function fuck()" ascii
    $s11 = ";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fu" ascii
    $s12 = " fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"P" ascii
    $s13 = "\"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(func" ascii
    $s14 = "eturn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s15 = "rn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s16 = "\"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"PDf\";})(),(func" ascii
    $s17 = "uck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\"" ascii
    $s18 = "n fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IP" ascii
    $s19 = "rn \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s20 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ar\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}