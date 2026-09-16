rule _20160921_378cbd2e27643682973c633e59454f9f_20160921_5f040a1454ca_4910 {
  meta:
    description = "datamaliciousorder - from files 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_9b80c329004df146d978cb7b31b22c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash2       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash3       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash4       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"

  strings:
    $s1 = ";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fu" ascii
    $s2 = "ck(){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "function fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s4 = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retur" ascii
    $s5 = "eturn \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}