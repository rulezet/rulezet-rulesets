rule TTP_XOR_QUAD_CurrentVersionRun_01bb {
  strings:
    $key_01bb = { 52 d4 [2] 76 da [2] 5d f6 [2] 73 d4 [2] 67 cf [2] 68 d5 [2] 76 c8 [2] 74 c9 [2] 6f cf [2] 73 c8 [2] 6f e7 }

  condition:
    any of them
}