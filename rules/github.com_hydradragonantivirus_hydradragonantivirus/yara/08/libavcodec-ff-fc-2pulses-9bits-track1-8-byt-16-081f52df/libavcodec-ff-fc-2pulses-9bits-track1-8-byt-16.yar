rule libavcodec_ff_fc_2pulses_9bits_track1__8_byt_16_ {
  strings:
    $a0 = { 01 03 06 08 0b 0d 10 12 15 17 1a 1c 1f 21 24 26 }

  condition:
    $a0
}