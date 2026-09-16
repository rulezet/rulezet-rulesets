rule TTP_XOR_QUAD_CurrentVersionRun_47bb {
  strings:
    $key_47bb = { 14 d4 [2] 30 da [2] 1b f6 [2] 35 d4 [2] 21 cf [2] 2e d5 [2] 30 c8 [2] 32 c9 [2] 29 cf [2] 35 c8 [2] 29 e7 }

  condition:
    any of them
}