rule TTP_XOR_QUAD_CurrentVersionRun_6fbb {
  strings:
    $key_6fbb = { 3c d4 [2] 18 da [2] 33 f6 [2] 1d d4 [2] 09 cf [2] 06 d5 [2] 18 c8 [2] 1a c9 [2] 01 cf [2] 1d c8 [2] 01 e7 }

  condition:
    any of them
}