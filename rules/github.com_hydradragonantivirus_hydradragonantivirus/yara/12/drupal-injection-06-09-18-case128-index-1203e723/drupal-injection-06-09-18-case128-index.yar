rule drupal_injection_06_09_18_case128_index {
  meta:
    description = "case128 - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-09"
    hash1       = "5d242e1686d8e321710c4311ad0e04574e107e34e3401ad0d89c407fea3cf247"

  strings:
                $s4  = "'error_log'); @ini_restore('display_errors');" fullword ascii
            $s7  = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); " ascii
    $s8  = "<?php" ascii
        $s10 = "kgeyAka2pka2VfYyA9IDE7IH0NCmVycm9yX3JlcG9ydGluZygwKTsNCmlmKCEka2pka2VfYykgeyBnbG9iYWwgJGtqZGtlX2M7ICRramRrZV9jID0gMTsNCmdsb2JhbC" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (all of them)
    ) or (all of them)
}