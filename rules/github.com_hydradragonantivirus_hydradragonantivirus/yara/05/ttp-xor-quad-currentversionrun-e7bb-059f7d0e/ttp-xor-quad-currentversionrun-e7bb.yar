rule TTP_XOR_QUAD_CurrentVersionRun_e7bb {
  strings:
    $key_e7bb = { b4 d4 [2] 90 da [2] bb f6 [2] 95 d4 [2] 81 cf [2] 8e d5 [2] 90 c8 [2] 92 c9 [2] 89 cf [2] 95 c8 [2] 89 e7 }

  condition:
    any of them
}