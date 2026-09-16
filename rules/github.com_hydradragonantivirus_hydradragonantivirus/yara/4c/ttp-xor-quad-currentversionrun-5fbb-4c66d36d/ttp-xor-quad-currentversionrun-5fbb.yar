rule TTP_XOR_QUAD_CurrentVersionRun_5fbb {
  strings:
    $key_5fbb = { 0c d4 [2] 28 da [2] 03 f6 [2] 2d d4 [2] 39 cf [2] 36 d5 [2] 28 c8 [2] 2a c9 [2] 31 cf [2] 2d c8 [2] 31 e7 }

  condition:
    any of them
}