rule TTP_XOR_QUAD_CurrentVersionRun_45bb {
  strings:
    $key_45bb = { 16 d4 [2] 32 da [2] 19 f6 [2] 37 d4 [2] 23 cf [2] 2c d5 [2] 32 c8 [2] 30 c9 [2] 2b cf [2] 37 c8 [2] 2b e7 }

  condition:
    any of them
}