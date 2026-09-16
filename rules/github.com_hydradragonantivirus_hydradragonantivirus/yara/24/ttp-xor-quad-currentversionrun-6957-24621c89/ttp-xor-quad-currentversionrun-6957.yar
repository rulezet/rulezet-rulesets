rule TTP_XOR_QUAD_CurrentVersionRun_6957 {
  strings:
    $key_6957 = { 3a 38 [2] 1e 36 [2] 35 1a [2] 1b 38 [2] 0f 23 [2] 00 39 [2] 1e 24 [2] 1c 25 [2] 07 23 [2] 1b 24 [2] 07 0b }

  condition:
    any of them
}