rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_448805735192_4427 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash3       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash4       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash5       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(fun" ascii
    $s2 = ",(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s3 = "(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){r" ascii
    $s4 = "fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GJ" ascii
    $s5 = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}