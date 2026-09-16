rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_37c1eae8c734_3573 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"

  strings:
    $s1 = "{return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ZWu\";}" ascii
    $s2 = "Oe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s3 = "(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(function fuck" ascii
    $s4 = "eturn \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s5 = "fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu" ascii
    $s6 = "k(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}