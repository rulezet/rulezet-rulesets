rule infected_08_25_18_blackhole_2 {
  meta:
    description = "redirect - file blackhole.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "a883fd80964028ce8578bcf99de10274ef0e7f6bfc02eafd787e963e00d645fe"

  strings:
    $s1 = "if(realpath(__FILE__)===realpath($_SERVER[" fullword ascii
    $s2 = "x77\\x78fp\\x73i\\x71\"]})){header(\"L\\x6f\\x63at\\x69on:\\x20/\",true,302);exit;}${${\"\\x47\\x4cOB\\x41\\x4c\\x53\"}[\"by\\x6" ascii
    $s3 = "<?php ${\"\\x47L\\x4f\\x42\\x41\\x4c\\x53\"}[\"\\x75\\x63\\x65z\\x6b\\x62\\x6e\\x77\\x65i\\x67\"]=\"s\\x74r\\x69n\\x67\";${\"GL" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (all of them)
    ) or (all of them)
}