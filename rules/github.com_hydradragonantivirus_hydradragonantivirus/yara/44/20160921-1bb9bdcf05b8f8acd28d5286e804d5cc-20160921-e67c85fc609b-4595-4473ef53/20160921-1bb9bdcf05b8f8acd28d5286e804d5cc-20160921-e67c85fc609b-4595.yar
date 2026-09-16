rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_e67c85fc609b_4595 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1 = "){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";" ascii
    $s2 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s3 = "k\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s4 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(functio" ascii
    $s5 = "function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}