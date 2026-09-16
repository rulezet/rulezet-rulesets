rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_8dce9d2aa0d1_5304 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s2 = "return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})()," ascii
    $s3 = "IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function" ascii
    $s4 = "unction fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s5 = "ck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"YAv\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}