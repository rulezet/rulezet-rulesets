rule _home_hawk_infected_12_22_19_user_emotet {
  meta:
    description = "12-22-19 - file user.php Emotet php serverside downloader file"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "30ed790766929a1be2d3a0095be41f3a1b7819505b826f779e109396236bad75"

  strings:
    $s1 = "goto" fullword ascii
    $s2 = "<?php function" fullword ascii
    $s3 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
    $s4 = "63e110ac5f971e41e77ef127575337d8aaeeae3b" ascii
    $s5 = "be5a8488b06f0640a63c80223a12d13e3d309f4d" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 100KB and
      (2 of them)
    ) or (all of them)
}