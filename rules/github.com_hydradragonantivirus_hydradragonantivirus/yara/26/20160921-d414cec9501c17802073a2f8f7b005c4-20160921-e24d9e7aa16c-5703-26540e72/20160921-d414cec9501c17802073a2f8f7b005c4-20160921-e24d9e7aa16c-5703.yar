rule _20160921_d414cec9501c17802073a2f8f7b005c4_20160921_e24d9e7aa16c_5703 {
  meta:
    description = "datamaliciousorder - from files 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash2       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash3       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1 = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";" ascii
    $s2 = "Pu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s3 = "){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii
    $s4 = "ck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\"" ascii
    $s5 = "fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}