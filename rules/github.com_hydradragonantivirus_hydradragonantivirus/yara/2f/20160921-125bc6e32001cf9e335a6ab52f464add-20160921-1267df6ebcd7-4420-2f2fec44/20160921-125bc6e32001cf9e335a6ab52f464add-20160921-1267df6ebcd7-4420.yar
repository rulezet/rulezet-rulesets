rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_1267df6ebcd7_4420 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash3       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash4       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = "\"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s2 = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s3 = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s4 = "{return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})" ascii
    $s5 = "urn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}