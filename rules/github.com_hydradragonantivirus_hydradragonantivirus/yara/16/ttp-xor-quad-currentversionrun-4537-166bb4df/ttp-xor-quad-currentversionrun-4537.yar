rule TTP_XOR_QUAD_CurrentVersionRun_4537 {
  strings:
    $key_4537 = { 16 58 [2] 32 56 [2] 19 7a [2] 37 58 [2] 23 43 [2] 2c 59 [2] 32 44 [2] 30 45 [2] 2b 43 [2] 37 44 [2] 2b 6b }

  condition:
    any of them
}