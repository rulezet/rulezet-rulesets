rule TTP_XOR_QUAD_CurrentVersionRun_7037 {
  strings:
    $key_7037 = { 23 58 [2] 07 56 [2] 2c 7a [2] 02 58 [2] 16 43 [2] 19 59 [2] 07 44 [2] 05 45 [2] 1e 43 [2] 02 44 [2] 1e 6b }

  condition:
    any of them
}