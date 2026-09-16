rule _20160921_5f040a1454cafc62100cb4449da0b7e2_20160921_5fbbbcb8f403_5276 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash2       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"
    hash3       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"
    hash4       = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"

  strings:
    $s1 = "(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";" ascii
    $s2 = "(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){re" ascii
    $s3 = "eturn \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(" ascii
    $s4 = "eturn \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s5 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"U" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}