rule infected_08_25_18_redirect_bienvenue_index {
  meta:
    description = "redirect - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "8cba56fbd792e090accc0f9489bc5900d9396382b2fd506c01efa178e9ce18c8"

  strings:
    $s1 = "<?php ${\"\\x47L\\x4fBAL\\x53\"}[\"\\x73\\x70fthl\\x6ary\"]=\"me\\x73s\\x61\\x67e\";${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x" ascii
    $s2 = "x\\x6fv\\x75\\x69v\"]}=\"w\\x68\\x6fi\\x73\\x2e\\x61r\\x69n\\x2e\\x6eet\";$fopock=\"\\x69pa\\x64\\x64\\x72\\x65\\x73\\x73\";if(!" ascii
    $s3 = "${\"G\\x4c\\x4f\\x42AL\\x53\"}[\"\\x70qdl\\x61i\\x6dmsjm\"]}.\"\\x20- \".${${\"\\x47\\x4c\\x4fB\\x41\\x4c\\x53\"}[\"\\x66f\\x6e" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 50KB and
      (all of them)
    ) or (all of them)
}