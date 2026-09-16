rule TTP_XOR_QUAD_CurrentVersionRun_d1bb {
  strings:
    $key_d1bb = { 82 d4 [2] a6 da [2] 8d f6 [2] a3 d4 [2] b7 cf [2] b8 d5 [2] a6 c8 [2] a4 c9 [2] bf cf [2] a3 c8 [2] bf e7 }

  condition:
    any of them
}