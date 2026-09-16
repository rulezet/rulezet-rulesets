rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_37c1eae8c734_3514 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash3       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash4       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = "eturn \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s2 = "Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";})(),(function" ascii
    $s3 = "{return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";}" ascii
    $s4 = "rn \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(fun" ascii
    $s5 = "(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){re" ascii
    $s6 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}