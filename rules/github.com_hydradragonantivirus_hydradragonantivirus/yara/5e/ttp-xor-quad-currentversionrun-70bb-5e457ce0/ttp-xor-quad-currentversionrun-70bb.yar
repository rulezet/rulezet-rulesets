rule TTP_XOR_QUAD_CurrentVersionRun_70bb {
  strings:
    $key_70bb = { 23 d4 [2] 07 da [2] 2c f6 [2] 02 d4 [2] 16 cf [2] 19 d5 [2] 07 c8 [2] 05 c9 [2] 1e cf [2] 02 c8 [2] 1e e7 }

  condition:
    any of them
}