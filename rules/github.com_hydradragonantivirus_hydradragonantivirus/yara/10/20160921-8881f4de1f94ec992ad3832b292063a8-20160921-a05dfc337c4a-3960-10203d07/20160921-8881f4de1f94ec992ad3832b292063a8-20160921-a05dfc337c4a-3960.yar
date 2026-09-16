rule _20160921_8881f4de1f94ec992ad3832b292063a8_20160921_a05dfc337c4a_3960 {
  meta:
    description = "datamaliciousorder - from files 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_a05dfc337c4ada28e05759b304eef904.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash2       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"
    hash3       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1 = "k(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\"" ascii
    $s2 = "ion fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s3 = "eturn \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s4 = "(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){" ascii
    $s5 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii
    $s6 = ")(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}