rule TTP_XOR_QUAD_CurrentVersionRun_4264 {
  strings:
    $key_4264 = { 11 0b [2] 35 05 [2] 1e 29 [2] 30 0b [2] 24 10 [2] 2b 0a [2] 35 17 [2] 37 16 [2] 2c 10 [2] 30 17 [2] 2c 38 }

  condition:
    any of them
}