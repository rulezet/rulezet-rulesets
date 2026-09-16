rule G_723_24__fitab__16_big_16_ {
  strings:
    $a0 = { 00 00 02 00 04 00 0e 00 0e 00 04 00 02 00 00 00 }

  condition:
    $a0
}