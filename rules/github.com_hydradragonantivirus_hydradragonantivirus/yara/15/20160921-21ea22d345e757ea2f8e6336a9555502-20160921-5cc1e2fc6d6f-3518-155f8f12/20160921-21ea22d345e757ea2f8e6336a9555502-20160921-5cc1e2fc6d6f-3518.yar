rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_5cc1e2fc6d6f_3518 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"

  strings:
    $s1 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retu" ascii
    $s2 = "{return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4 = "rn \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s5 = "function fuck(){return \"GNm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s6 = "\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}