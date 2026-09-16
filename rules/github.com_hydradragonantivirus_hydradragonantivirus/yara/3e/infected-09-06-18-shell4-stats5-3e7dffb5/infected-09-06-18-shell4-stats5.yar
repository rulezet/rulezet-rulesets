rule infected_09_06_18_shell4_stats5 {
  meta:
    description = "shell4 - file stats5.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-06"
    hash1       = "8053c1ced5fe5f93dded31afdda01c9469be7bb025fdd2cd192903c4fccec40f"

  strings:
    $s1 = "ZXJyb3JfcmVwb3J0aW5nKDApOyBpZiAoaXNzZXQoJF9QT1NUWydjb29raWVzX2UnXSkpIHtldmFsKGJhc2U2NF9kZWNvZGUoJF9QT1NUWydjb29raWVzX2UnXSkpO30g"  
    $s2 = "@error_reporting(0); @eval(base64_decode(" ascii
    $s3 = "<?php" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}