rule _20160921_a210d5e93bf8b06dbd0a1b262abe210f_20160921_b6d1e9aee3a0_5602 {
  meta:
    description = "datamaliciousorder - from files 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash2       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"

  strings:
    $s1 = "n \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2 = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s3 = "){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";}" ascii
    $s4 = "n fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s5 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}