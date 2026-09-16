rule _20160921_8b9d3c425718975422f8fe0d71119686_20160921_afb633ee817d_3088 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1 = "Oh\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s2 = "function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){re" ascii
    $s3 = "rn \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s5 = "\"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(),(funct" ascii
    $s6 = "k(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Wo0\"" ascii
    $s7 = "})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}