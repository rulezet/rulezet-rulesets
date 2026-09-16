rule TTP_XOR_QUAD_CurrentVersionRun_f0bb {
  strings:
    $key_f0bb = { a3 d4 [2] 87 da [2] ac f6 [2] 82 d4 [2] 96 cf [2] 99 d5 [2] 87 c8 [2] 85 c9 [2] 9e cf [2] 82 c8 [2] 9e e7 }

  condition:
    any of them
}