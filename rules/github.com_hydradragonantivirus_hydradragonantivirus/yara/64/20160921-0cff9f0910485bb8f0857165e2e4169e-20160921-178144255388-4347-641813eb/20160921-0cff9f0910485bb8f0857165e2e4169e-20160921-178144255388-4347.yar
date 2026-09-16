rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_178144255388_4347 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash3       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash4       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash5       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash6       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"
    hash7       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"
    hash8       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "ion f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s2 = "Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function" ascii
    $s3 = "{return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(" ascii
    $s4 = "eturn \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})()," ascii
    $s5 = "ion f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}