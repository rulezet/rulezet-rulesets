rule libavformat_CODEC_ID_AMR_WB_packet_size__8_byt_16_ {
  strings:
    $a0 = { 12 18 21 25 29 2f 33 3b 3d 06 06 00 00 00 01 01 }

  condition:
    $a0
}