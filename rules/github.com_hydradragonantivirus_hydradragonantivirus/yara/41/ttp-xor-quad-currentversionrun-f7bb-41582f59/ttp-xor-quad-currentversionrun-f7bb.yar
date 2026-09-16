rule TTP_XOR_QUAD_CurrentVersionRun_f7bb {
  strings:
    $key_f7bb = { a4 d4 [2] 80 da [2] ab f6 [2] 85 d4 [2] 91 cf [2] 9e d5 [2] 80 c8 [2] 82 c9 [2] 99 cf [2] 85 c8 [2] 99 e7 }

  condition:
    any of them
}