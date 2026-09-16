rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_19fa56ffee6d_4234 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash3       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash4       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s2 = "Oe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s3 = "turn \"Jh\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})()," ascii
    $s4 = "\"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Zy\";})(),(func" ascii
    $s5 = "eturn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vb\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}