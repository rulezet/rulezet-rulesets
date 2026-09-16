rule TTP_XOR_QUAD_CurrentVersionRun_b7bb {
  strings:
    $key_b7bb = { e4 d4 [2] c0 da [2] eb f6 [2] c5 d4 [2] d1 cf [2] de d5 [2] c0 c8 [2] c2 c9 [2] d9 cf [2] c5 c8 [2] d9 e7 }

  condition:
    any of them
}