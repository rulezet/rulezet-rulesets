rule TTP_XOR_QUAD_CurrentVersionRun_b3bb {
  strings:
    $key_b3bb = { e0 d4 [2] c4 da [2] ef f6 [2] c1 d4 [2] d5 cf [2] da d5 [2] c4 c8 [2] c6 c9 [2] dd cf [2] c1 c8 [2] dd e7 }

  condition:
    any of them
}