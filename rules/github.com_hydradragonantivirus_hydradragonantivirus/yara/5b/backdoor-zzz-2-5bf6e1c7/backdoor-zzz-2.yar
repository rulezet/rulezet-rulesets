rule backdoor_zzz_2 {
  meta:
    description = "work1 - file backdoor_zzz_2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "56114895e46ae1b71f3d8620e04703892bead737b774446a28e649da3919c1df"

  strings:
    $s1 = "if (file_exists(\"cqenpf76ipf2.php.suspected\")) rename (\"cqenpf76ipf2.php.suspected\", \"cqenpf76ipf2.php\");" fullword ascii
    $s2 = "RewriteRule ^([A-Za-z0-9-]+).html$ cqenpf76ipf2.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii

  condition:
    (uint16(0) == 0x3c0a and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}