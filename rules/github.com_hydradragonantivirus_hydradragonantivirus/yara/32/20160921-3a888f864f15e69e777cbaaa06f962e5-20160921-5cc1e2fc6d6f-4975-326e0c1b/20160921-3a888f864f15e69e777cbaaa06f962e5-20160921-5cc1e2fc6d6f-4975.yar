rule _20160921_3a888f864f15e69e777cbaaa06f962e5_20160921_5cc1e2fc6d6f_4975 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash2       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"

  strings:
    $s1 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s2 = "(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s3 = "uck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml" ascii
    $s4 = "eturn \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}