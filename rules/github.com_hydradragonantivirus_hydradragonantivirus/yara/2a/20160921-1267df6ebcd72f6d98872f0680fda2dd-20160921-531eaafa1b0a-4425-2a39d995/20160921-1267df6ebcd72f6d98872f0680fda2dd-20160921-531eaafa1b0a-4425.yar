rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_531eaafa1b0a_4425 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash3       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash4       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash5       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "tion fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return " ascii
    $s2 = "k(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})" ascii
    $s3 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(funct" ascii
    $s4 = "(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";" ascii
    $s5 = "eturn \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}