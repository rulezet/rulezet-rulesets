rule _20160921_4b85b9629682d9cbd379b3404bd09eb1_20160921_66566a9bbc78_5116 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash2       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash3       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash4       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = ",(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){r" ascii
    $s2 = "0(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\"" ascii
    $s3 = "Gn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(functio" ascii
    $s4 = "n f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"I" ascii
    $s5 = "\"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}