rule TTP_XOR_QUAD_CurrentVersionRun_46bb {
  strings:
    $key_46bb = { 15 d4 [2] 31 da [2] 1a f6 [2] 34 d4 [2] 20 cf [2] 2f d5 [2] 31 c8 [2] 33 c9 [2] 28 cf [2] 34 c8 [2] 28 e7 }

  condition:
    any of them
}