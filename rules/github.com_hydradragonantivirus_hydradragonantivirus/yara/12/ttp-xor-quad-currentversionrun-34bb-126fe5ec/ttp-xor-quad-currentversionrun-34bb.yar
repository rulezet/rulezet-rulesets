rule TTP_XOR_QUAD_CurrentVersionRun_34bb {
  strings:
    $key_34bb = { 67 d4 [2] 43 da [2] 68 f6 [2] 46 d4 [2] 52 cf [2] 5d d5 [2] 43 c8 [2] 41 c9 [2] 5a cf [2] 46 c8 [2] 5a e7 }

  condition:
    any of them
}