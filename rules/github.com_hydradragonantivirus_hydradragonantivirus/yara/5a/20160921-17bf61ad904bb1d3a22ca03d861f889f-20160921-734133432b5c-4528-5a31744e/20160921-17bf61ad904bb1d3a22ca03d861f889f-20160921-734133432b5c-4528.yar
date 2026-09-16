rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_734133432b5c_4528 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_a05dfc337c4ada28e05759b304eef904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash3       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"

  strings:
    $s1 = "urn \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(fu" ascii
    $s2 = ";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck" ascii
    $s3 = "){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";}" ascii
    $s4 = "\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function " ascii
    $s5 = "uck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}