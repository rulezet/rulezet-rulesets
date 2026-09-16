rule TTP_XOR_QUAD_CurrentVersionRun_4257 {
  strings:
    $key_4257 = { 11 38 [2] 35 36 [2] 1e 1a [2] 30 38 [2] 24 23 [2] 2b 39 [2] 35 24 [2] 37 25 [2] 2c 23 [2] 30 24 [2] 2c 0b }

  condition:
    any of them
}