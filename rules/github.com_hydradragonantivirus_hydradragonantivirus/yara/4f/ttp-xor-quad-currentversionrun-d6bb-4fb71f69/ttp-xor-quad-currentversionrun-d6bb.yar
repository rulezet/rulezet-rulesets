rule TTP_XOR_QUAD_CurrentVersionRun_d6bb {
  strings:
    $key_d6bb = { 85 d4 [2] a1 da [2] 8a f6 [2] a4 d4 [2] b0 cf [2] bf d5 [2] a1 c8 [2] a3 c9 [2] b8 cf [2] a4 c8 [2] b8 e7 }

  condition:
    any of them
}