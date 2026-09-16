rule _20160921_4809ff2679793c2b9af03e18ec3702ef_20160921_6d7b654a484a_3725 {
  meta:
    description = "datamaliciousorder - from files 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_6d7b654a484acab4abb3060ebc68a164.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash2       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"

  strings:
    $s1 = "\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function f" ascii
    $s2 = "nction fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s3 = "s\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s4 = "\"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(func" ascii
    $s5 = "RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s6 = "k(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}