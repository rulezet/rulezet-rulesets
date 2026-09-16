rule TTP_XOR_QUAD_CurrentVersionRun_36bb {
  strings:
    $key_36bb = { 65 d4 [2] 41 da [2] 6a f6 [2] 44 d4 [2] 50 cf [2] 5f d5 [2] 41 c8 [2] 43 c9 [2] 58 cf [2] 44 c8 [2] 58 e7 }

  condition:
    any of them
}