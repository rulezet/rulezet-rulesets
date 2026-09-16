rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_3701 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash4       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1 = "k(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\"" ascii
    $s2 = "),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){" ascii
    $s3 = " \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\";})(),(func" ascii
    $s4 = "\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s5 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s6 = "ion fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}