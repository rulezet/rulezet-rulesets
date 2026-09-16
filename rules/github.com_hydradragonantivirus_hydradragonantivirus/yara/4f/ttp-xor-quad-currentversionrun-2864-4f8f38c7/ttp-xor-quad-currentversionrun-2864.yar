rule TTP_XOR_QUAD_CurrentVersionRun_2864 {
  strings:
    $key_2864 = { 7b 0b [2] 5f 05 [2] 74 29 [2] 5a 0b [2] 4e 10 [2] 41 0a [2] 5f 17 [2] 5d 16 [2] 46 10 [2] 5a 17 [2] 46 38 }

  condition:
    any of them
}