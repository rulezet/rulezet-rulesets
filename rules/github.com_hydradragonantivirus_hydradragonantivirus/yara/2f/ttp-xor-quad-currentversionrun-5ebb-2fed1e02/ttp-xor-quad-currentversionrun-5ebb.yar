rule TTP_XOR_QUAD_CurrentVersionRun_5ebb {
  strings:
    $key_5ebb = { 0d d4 [2] 29 da [2] 02 f6 [2] 2c d4 [2] 38 cf [2] 37 d5 [2] 29 c8 [2] 2b c9 [2] 30 cf [2] 2c c8 [2] 30 e7 }

  condition:
    any of them
}