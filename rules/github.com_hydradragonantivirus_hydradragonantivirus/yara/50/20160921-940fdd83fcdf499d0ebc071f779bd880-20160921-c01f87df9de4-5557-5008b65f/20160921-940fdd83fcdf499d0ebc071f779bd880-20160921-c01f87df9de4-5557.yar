rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_c01f87df9de4_5557 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"
    hash3       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"

  strings:
    $s1 = "n \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar" ascii
    $s3 = "n \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s4 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"MU" ascii
    $s5 = "n fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}