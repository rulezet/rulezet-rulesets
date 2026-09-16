rule TTP_XOR_QUAD_CurrentVersionRun_7057 {
  strings:
    $key_7057 = { 23 38 [2] 07 36 [2] 2c 1a [2] 02 38 [2] 16 23 [2] 19 39 [2] 07 24 [2] 05 25 [2] 1e 23 [2] 02 24 [2] 1e 0b }

  condition:
    any of them
}