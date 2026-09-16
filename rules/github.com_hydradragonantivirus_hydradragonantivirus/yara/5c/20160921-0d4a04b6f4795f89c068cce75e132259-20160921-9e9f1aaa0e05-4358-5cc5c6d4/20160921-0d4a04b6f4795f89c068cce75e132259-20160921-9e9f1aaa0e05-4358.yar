rule _20160921_0d4a04b6f4795f89c068cce75e132259_20160921_9e9f1aaa0e05_4358 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash2       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"

  strings:
    $s1 = "){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s2 = "return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})()" ascii
    $s3 = "n fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"I" ascii
    $s4 = "eturn \"Ve\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s5 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}