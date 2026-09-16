rule TTP_XOR_QUAD_CurrentVersionRun_56bb {
  strings:
    $key_56bb = { 05 d4 [2] 21 da [2] 0a f6 [2] 24 d4 [2] 30 cf [2] 3f d5 [2] 21 c8 [2] 23 c9 [2] 38 cf [2] 24 c8 [2] 38 e7 }

  condition:
    any of them
}