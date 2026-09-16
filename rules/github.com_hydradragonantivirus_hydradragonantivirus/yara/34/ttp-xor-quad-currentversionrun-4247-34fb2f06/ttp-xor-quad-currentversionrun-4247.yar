rule TTP_XOR_QUAD_CurrentVersionRun_4247 {
  strings:
    $key_4247 = { 11 28 [2] 35 26 [2] 1e 0a [2] 30 28 [2] 24 33 [2] 2b 29 [2] 35 34 [2] 37 35 [2] 2c 33 [2] 30 34 [2] 2c 1b }

  condition:
    any of them
}