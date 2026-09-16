rule Electronic_Arts_TQI_base_table2__8_byt_64_ {
  strings:
    $a0 = { 08 10 13 16 1a 1b 1d 22 10 10 16 18 1b 1d 22 25 13 16 1a 1b 1d 22 22 26 16 16 1a 1b 1d 22 25 28 16 1a 1b 1d 20 23 28 30 1a 1b 1d 20 23 28 30 3a 1a 1b 1d 22 26 2e 38 45 1b 1d 23 26 2e 38 45 53 }

  condition:
    $a0
}