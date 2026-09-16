rule TTP_XOR_QUAD_CurrentVersionRun_7046 {
  strings:
    $key_7046 = { 23 29 [2] 07 27 [2] 2c 0b [2] 02 29 [2] 16 32 [2] 19 28 [2] 07 35 [2] 05 34 [2] 1e 32 [2] 02 35 [2] 1e 1a }

  condition:
    any of them
}