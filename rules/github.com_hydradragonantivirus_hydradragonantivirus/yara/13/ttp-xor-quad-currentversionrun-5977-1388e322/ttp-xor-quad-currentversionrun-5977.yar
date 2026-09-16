rule TTP_XOR_QUAD_CurrentVersionRun_5977 {
  strings:
    $key_5977 = { 0a 18 [2] 2e 16 [2] 05 3a [2] 2b 18 [2] 3f 03 [2] 30 19 [2] 2e 04 [2] 2c 05 [2] 37 03 [2] 2b 04 [2] 37 2b }

  condition:
    any of them
}