rule _20160921_18eedffe02de43ba2ee494451deba790_20160921_1e5a9eb0eb0b_4554 {
  meta:
    description = "datamaliciousorder - from files 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash2       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash3       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash4       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash5       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"

  strings:
    $s1 = "(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){ret" ascii
    $s2 = "(){return \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s3 = "We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function" ascii
    $s4 = "ion fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return " ascii
    $s5 = ",(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}