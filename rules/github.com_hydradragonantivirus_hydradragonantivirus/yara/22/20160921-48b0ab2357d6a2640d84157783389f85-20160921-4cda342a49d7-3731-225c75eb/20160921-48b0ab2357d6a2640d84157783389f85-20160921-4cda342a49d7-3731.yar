rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_4cda342a49d7_3731 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash3       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash4       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash5       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"
    hash6       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){r" ascii
    $s2 = "tion fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s3 = "turn \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(f" ascii
    $s4 = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s5 = "ction fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s6 = "urn \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}