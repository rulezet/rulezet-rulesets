rule Ultima_Online_uodemo_dat_algorithm_key__32_lil_32_ {
  strings:
    $a0 = { 98 4c aa f7 67 c0 62 bf 34 43 52 0b d0 a2 28 bc d1 c2 57 6b aa 43 38 23 10 02 6d c0 04 f8 d4 38 }

  condition:
    $a0
}