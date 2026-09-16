rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_734133432b5c_2948 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_a05dfc337c4ada28e05759b304eef904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash3       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"

  strings:
    $s1 = "urn \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(" ascii
    $s2 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii
    $s3 = "),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(" ascii
    $s4 = "fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"O" ascii
    $s5 = "ck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Fv\";" ascii
    $s6 = " fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s7 = "rn \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}