rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_2111693a6587_3297 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash3       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash4       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"
    hash5       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1 = "turn \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s2 = "UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(functio" ascii
    $s3 = "tion fuck(){return \"OQr\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s4 = "eturn \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s5 = "eturn \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})()" ascii
    $s6 = "})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OPz\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}