rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_db727bb0ba7a_5251 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = "turn \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})()," ascii
    $s2 = ")(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuc" ascii
    $s3 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return" ascii
    $s4 = "\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"YQt\";})(),(function " ascii
    $s5 = "n \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}