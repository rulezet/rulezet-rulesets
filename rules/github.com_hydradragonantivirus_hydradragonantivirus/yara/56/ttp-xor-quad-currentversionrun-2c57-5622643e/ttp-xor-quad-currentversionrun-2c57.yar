rule TTP_XOR_QUAD_CurrentVersionRun_2c57 {
  strings:
    $key_2c57 = { 7f 38 [2] 5b 36 [2] 70 1a [2] 5e 38 [2] 4a 23 [2] 45 39 [2] 5b 24 [2] 59 25 [2] 42 23 [2] 5e 24 [2] 42 0b }

  condition:
    any of them
}