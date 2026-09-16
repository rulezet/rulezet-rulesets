rule _20160921_a84d89efd5400c906c1132a56b0ef679_20160921_e354814fb086_2154 {
  meta:
    description = "datamaliciousorder - from files 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash2       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "{return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MIl\";}" ascii
    $s2 = "tion fuck(){return \"CCb\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retur" ascii
    $s3 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function" ascii
    $s4 = "ction fuck(){return \"Jh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5 = "nction fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s6 = "on fuck(){return \"Ot\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii
    $s7 = "return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})" ascii
    $s8 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"ZLd\";})(),(function " ascii
    $s9 = "eturn \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}