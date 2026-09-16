rule _20160921_57d7efd4078096b801e379ee02f0feec_20160921_70fc4d2c06ba_2087 {
  meta:
    description = "datamaliciousorder - from files 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash2       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash3       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"
    hash4       = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1 = "Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s2 = "fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy" ascii
    $s3 = "urn \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s4 = "k(){return \"TTs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn" ascii
    $s5 = ";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuc" ascii
    $s6 = "})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s7 = "n \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(f" ascii
    $s8 = "(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){re" ascii
    $s9 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZLd\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}