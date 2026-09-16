rule _20160921_262709d34b477380050375a3b5b2833b_20160921_2bac0af1f20f_2328 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash3       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"

  strings:
    $s1 = "on fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s2 = ";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuc" ascii
    $s3 = "LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s4 = "(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s5 = "(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";}" ascii
    $s6 = " \"DHd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s7 = "rn \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ZVi\";})(),(f" ascii
    $s8 = "turn \"Ve\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}