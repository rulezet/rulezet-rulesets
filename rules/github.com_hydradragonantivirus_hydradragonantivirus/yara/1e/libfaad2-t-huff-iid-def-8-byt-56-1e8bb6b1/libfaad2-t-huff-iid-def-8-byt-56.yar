rule libfaad2_t_huff_iid_def__8_byt_56_ {
  strings:
    $a0 = { E1 01 E0 02 E2 03 DF 04 E3 05 DE 06 E4 07 DD 08 E5 09 DC 0A E6 0B DB 0C E7 0D E8 0E DA 0F 10 11 E9 D9 12 13 14 15 16 17 EA D3 D4 D5 18 19 1A 1B D6 D7 D8 EB EC ED EE EF }

  condition:
    $a0
}