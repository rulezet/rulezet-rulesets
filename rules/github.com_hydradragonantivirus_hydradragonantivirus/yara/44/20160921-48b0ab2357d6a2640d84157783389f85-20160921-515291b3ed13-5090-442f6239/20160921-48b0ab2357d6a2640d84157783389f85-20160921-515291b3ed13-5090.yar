rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_515291b3ed13_5090 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js, 20160921_e6771cfa257410eb61913de76cb777a8.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash3       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"
    hash4       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"
    hash5       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(" ascii
    $s2 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe" ascii
    $s3 = "urn \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(func" ascii
    $s5 = "fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"A" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}