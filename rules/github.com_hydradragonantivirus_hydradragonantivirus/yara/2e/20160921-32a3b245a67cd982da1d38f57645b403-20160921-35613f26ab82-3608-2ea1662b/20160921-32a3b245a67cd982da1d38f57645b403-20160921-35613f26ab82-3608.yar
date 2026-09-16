rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_3608 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_5cabcf77c626e288d5cbd9104a914ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash3       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"

  strings:
    $s1 = "o\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function" ascii
    $s2 = "uck(){return \"Np\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s3 = "tion fuck(){return \"Dc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return " ascii
    $s4 = "ion fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s5 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s6 = "turn \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}