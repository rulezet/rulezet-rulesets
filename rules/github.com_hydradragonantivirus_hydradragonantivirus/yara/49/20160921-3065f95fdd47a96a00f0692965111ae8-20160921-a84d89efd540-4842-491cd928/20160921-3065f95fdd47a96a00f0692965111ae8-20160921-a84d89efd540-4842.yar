rule _20160921_3065f95fdd47a96a00f0692965111ae8_20160921_a84d89efd540_4842 {
  meta:
    description = "datamaliciousorder - from files 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash2       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"

  strings:
    $s1 = "v\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function " ascii
    $s2 = "tion fuck(){return \"XFd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s3 = "ion fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function" ascii
    $s5 = "rn \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}