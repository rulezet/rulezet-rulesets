rule libavcodec_ff_nelly_delta_table__16_lil_64_ {
  strings:
    $a0 = { 33 D2 34 DB 1A E1 6F E5 C4 E8 8F EB 09 EE 39 F0 4D F2 2A F4 DC F5 86 F7 12 F9 99 FA 08 FC 6C FD B7 FE FF FF 51 01 B8 02 3D 04 E8 05 AA 07 81 09 98 0B F1 0D DA 10 9F 14 DE 19 DA 1F 5C 27 AF 32 }

  condition:
    $a0
}