rule _20160921_20daf816cda5af37e984359023f15db2_20160921_5230866e44ed_4662 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_5230866e44eda4e054d929933fdfdae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"

  strings:
    $s1 = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){re" ascii
    $s2 = "ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"PDf\";})(),(functi" ascii
    $s3 = "tion fuck(){return \"Wo0\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s4 = "){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"To\";})" ascii
    $s5 = " fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"P" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}