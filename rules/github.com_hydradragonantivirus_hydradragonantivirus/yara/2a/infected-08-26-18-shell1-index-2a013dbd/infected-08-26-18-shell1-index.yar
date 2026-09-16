rule infected_08_26_18_shell1_index {
  meta:
    description = "shell1 - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-26"
    hash1       = "4b00a6c47568876d81d3ffc1b9ae3721ffc4e91086f86d266526853d17e56c88"

  strings:
    $s1 = "header(\"location: 1.php?cmd=login_submit&id=$praga$praga&session=$praga$praga\");" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}