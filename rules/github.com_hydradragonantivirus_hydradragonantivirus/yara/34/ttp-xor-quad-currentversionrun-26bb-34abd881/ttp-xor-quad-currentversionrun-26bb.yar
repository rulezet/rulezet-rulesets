rule TTP_XOR_QUAD_CurrentVersionRun_26bb {
  strings:
    $key_26bb = { 75 d4 [2] 51 da [2] 7a f6 [2] 54 d4 [2] 40 cf [2] 4f d5 [2] 51 c8 [2] 53 c9 [2] 48 cf [2] 54 c8 [2] 48 e7 }

  condition:
    any of them
}