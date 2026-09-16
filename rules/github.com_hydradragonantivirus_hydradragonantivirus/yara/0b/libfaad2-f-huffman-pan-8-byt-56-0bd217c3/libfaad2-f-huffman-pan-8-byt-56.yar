rule libfaad2_f_huffman_pan__8_byt_56_ {
  strings:
    $a0 = { F1 01 F0 02 F2 03 04 05 EF F3 06 07 EE F4 08 09 ED F5 0A 0B EC F6 0C 0D EB F7 EA 0E F8 0F 10 11 E9 F9 12 13 E7 14 15 16 E8 FA FB 17 18 19 E4 E6 FC FE 1A 1B E3 E5 FD FF }

  condition:
    $a0
}