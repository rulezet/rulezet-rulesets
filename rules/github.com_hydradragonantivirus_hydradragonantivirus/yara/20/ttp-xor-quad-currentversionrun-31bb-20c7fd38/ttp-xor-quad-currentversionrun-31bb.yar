rule TTP_XOR_QUAD_CurrentVersionRun_31bb {
  strings:
    $key_31bb = { 62 d4 [2] 46 da [2] 6d f6 [2] 43 d4 [2] 57 cf [2] 58 d5 [2] 46 c8 [2] 44 c9 [2] 5f cf [2] 43 c8 [2] 5f e7 }

  condition:
    any of them
}