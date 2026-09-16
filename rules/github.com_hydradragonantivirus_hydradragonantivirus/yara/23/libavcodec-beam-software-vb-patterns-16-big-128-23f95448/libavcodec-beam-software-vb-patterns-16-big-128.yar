rule libavcodec_Beam_software_vb_patterns__16_big_128_ {
  strings:
    $a0 = { 06 60 ff 00 cc cc f0 00 88 88 00 0f 11 11 fe c8 8c ef 13 7f f7 31 c8 00 00 8c 00 13 31 00 cc 00 00 cc 00 33 33 00 0f f0 66 66 00 f0 0f 00 22 22 44 44 f6 00 8c c8 00 6f 13 31 31 8c c8 13 33 cc 66 00 0c c0 00 66 03 30 f9 00 c8 8c 00 9f 31 13 60 00 08 80 00 06 01 10 cc 88 fc 00 00 cf 88 cc 00 3f 11 33 33 11 f3 00 6f f6 06 03 08 c6 8c 63 c6 31 63 10 c0 60 01 36 13 6c 36 c8 6c 80 32 4c }

  condition:
    $a0
}