rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_5e9244484429_4681 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash3       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1 = " fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s2 = "tion fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return " ascii
    $s3 = "turn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(" ascii
    $s4 = "function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5 = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}