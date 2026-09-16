rule TTP_XOR_QUAD_CurrentVersionRun_50bb {
  strings:
    $key_50bb = { 03 d4 [2] 27 da [2] 0c f6 [2] 22 d4 [2] 36 cf [2] 39 d5 [2] 27 c8 [2] 25 c9 [2] 3e cf [2] 22 c8 [2] 3e e7 }

  condition:
    any of them
}