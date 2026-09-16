rule _20160921_202394e6610dfa0f27f737c781d5c579_20160921_68e1fc90afca_3494 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_68e1fc90afca497654d8f771197c2097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"

  strings:
    $s1 = "nction f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){retu" ascii
    $s2 = "return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MBb\";})(" ascii
    $s3 = "f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s4 = "ion f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s5 = ",(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000()" ascii
    $s6 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}