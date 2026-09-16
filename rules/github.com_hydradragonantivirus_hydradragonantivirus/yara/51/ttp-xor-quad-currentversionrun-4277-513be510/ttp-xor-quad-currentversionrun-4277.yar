rule TTP_XOR_QUAD_CurrentVersionRun_4277 {
  strings:
    $key_4277 = { 11 18 [2] 35 16 [2] 1e 3a [2] 30 18 [2] 24 03 [2] 2b 19 [2] 35 04 [2] 37 05 [2] 2c 03 [2] 30 04 [2] 2c 2b }

  condition:
    any of them
}