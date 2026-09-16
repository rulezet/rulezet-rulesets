rule libavcodec_ff_fc_2pulses_9bits_track2_gray__8_byt_32_ {
  strings:
    $a0 = { 00 02 05 04 0c 0a 07 09 19 18 14 16 0e 0f 13 11 24 1f 15 1a 01 06 10 0b 1b 1d 20 1e 27 25 22 23 }

  condition:
    $a0
}