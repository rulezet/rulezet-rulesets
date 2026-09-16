rule TTP_XOR_QUAD_CurrentVersionRun_74bb {
  strings:
    $key_74bb = { 27 d4 [2] 03 da [2] 28 f6 [2] 06 d4 [2] 12 cf [2] 1d d5 [2] 03 c8 [2] 01 c9 [2] 1a cf [2] 06 c8 [2] 1a e7 }

  condition:
    any of them
}