rule backdoor_zzz {
  meta:
    description = "PHP - file backdoor_zzz.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "edea8d3d181d9b57ebdbbe63ebd9d086f1b5f8b0978df47da45043420616cd5f"

  strings:
    $s1 = "if (file_exists(\"x15q5mcjtk.php.suspected\")) rename (\"x15q5mcjtk.php.suspected\", \"x15q5mcjtk.php\");" fullword ascii
    $s2 = "RewriteRule ^([A-Za-z0-9-]+).html$ x15q5mcjtk.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}