rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_5745920040b3_4727 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash3       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash4       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "n fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2 = " fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s3 = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck" ascii
    $s4 = "rn \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(" ascii
    $s5 = "urn \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}