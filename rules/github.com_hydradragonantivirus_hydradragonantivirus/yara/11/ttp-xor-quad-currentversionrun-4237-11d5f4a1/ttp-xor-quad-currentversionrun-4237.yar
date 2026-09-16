rule TTP_XOR_QUAD_CurrentVersionRun_4237 {
  strings:
    $key_4237 = { 11 58 [2] 35 56 [2] 1e 7a [2] 30 58 [2] 24 43 [2] 2b 59 [2] 35 44 [2] 37 45 [2] 2c 43 [2] 30 44 [2] 2c 6b }

  condition:
    any of them
}