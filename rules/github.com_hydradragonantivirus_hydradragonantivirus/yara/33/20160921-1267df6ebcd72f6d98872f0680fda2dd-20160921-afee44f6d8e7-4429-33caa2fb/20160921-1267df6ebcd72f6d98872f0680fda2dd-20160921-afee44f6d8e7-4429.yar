rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_afee44f6d8e7_4429 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash3       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash4       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1 = " fuck(){return \"Ot\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"I" ascii
    $s2 = "unction fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s3 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"QTc\";})(),(function fu" ascii
    $s4 = "\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function f" ascii
    $s5 = "ion fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}