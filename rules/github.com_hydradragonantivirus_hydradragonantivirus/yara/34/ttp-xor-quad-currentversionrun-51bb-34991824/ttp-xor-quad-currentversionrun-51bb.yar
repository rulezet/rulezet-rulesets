rule TTP_XOR_QUAD_CurrentVersionRun_51bb {
  strings:
    $key_51bb = { 02 d4 [2] 26 da [2] 0d f6 [2] 23 d4 [2] 37 cf [2] 38 d5 [2] 26 c8 [2] 24 c9 [2] 3f cf [2] 23 c8 [2] 3f e7 }

  condition:
    any of them
}