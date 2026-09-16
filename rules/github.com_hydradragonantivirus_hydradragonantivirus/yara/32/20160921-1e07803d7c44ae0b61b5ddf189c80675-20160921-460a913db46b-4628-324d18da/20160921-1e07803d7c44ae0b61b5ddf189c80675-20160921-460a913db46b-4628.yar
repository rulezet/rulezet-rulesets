rule _20160921_1e07803d7c44ae0b61b5ddf189c80675_20160921_460a913db46b_4628 {
  meta:
    description = "datamaliciousorder - from files 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash2       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash3       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1 = "fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s2 = "urn \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(f" ascii
    $s3 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg" ascii
    $s4 = "eturn \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s5 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}