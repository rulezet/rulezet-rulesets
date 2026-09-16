rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_7e2de7c26f13_3908 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash3       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash4       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash5       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1 = "{return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s2 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s3 = "return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})" ascii
    $s4 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s5 = "){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";}" ascii
    $s6 = "(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}