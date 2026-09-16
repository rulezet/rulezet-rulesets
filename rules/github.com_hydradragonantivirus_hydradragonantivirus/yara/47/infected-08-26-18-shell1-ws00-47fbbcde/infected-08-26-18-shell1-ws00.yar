rule infected_08_26_18_shell1_ws00 {
  meta:
    description = "shell1 - file ws00.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-26"
    hash1       = "68bcfb4a9fe324ebbeed2e1c87e5670f5a776ea030d983a9d38fa8948d56a43d"

  strings:
    $s1 = "eval($_(" fullword ascii
    $s2 = "$_=\"\\x62\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\";" fullword ascii
    $s3 = "/*.*/"
    $s4 = "<?php"

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}