rule TTP_XOR_QUAD_CurrentVersionRun_7fbb {
  strings:
    $key_7fbb = { 2c d4 [2] 08 da [2] 23 f6 [2] 0d d4 [2] 19 cf [2] 16 d5 [2] 08 c8 [2] 0a c9 [2] 11 cf [2] 0d c8 [2] 11 e7 }

  condition:
    any of them
}