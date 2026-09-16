rule libavcodec_Video_XL_delta_table_xl_table__16_lil_64_ {
  strings:
    $a0 = { 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0c 00 0f 00 14 00 19 00 22 00 2e 00 40 00 52 00 5e 00 67 00 6c 00 71 00 74 00 77 00 78 00 79 00 7a 00 7b 00 7c 00 7d 00 7e 00 7f 00 }

  condition:
    $a0
}