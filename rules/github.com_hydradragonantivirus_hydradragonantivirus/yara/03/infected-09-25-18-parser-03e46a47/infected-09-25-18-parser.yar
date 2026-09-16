rule infected_09_25_18_Parser {
  meta:
    description = "shell2 - file Parser.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-25"
    hash1       = "bc3658527871f653b7034dc05e4e5f5f589723e273da2fc7a9ea6c4045e6dc7f"

  strings:
    $s1 = "* Descriptor" fullword ascii
    $s2 = "* Request Parser Variables" fullword ascii
    $s3 = "* Show Parser UTF-8 Chars" fullword ascii
    $s4 = "$p28 = \"\\x70\\x72\\x65\\x67\\x5F\\x72\\x65\\x70\\x6C\\x61\\x63\\x65\";" fullword ascii
    $s5 = "* Router" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 40KB and
      (all of them)
    ) or (all of them)
}