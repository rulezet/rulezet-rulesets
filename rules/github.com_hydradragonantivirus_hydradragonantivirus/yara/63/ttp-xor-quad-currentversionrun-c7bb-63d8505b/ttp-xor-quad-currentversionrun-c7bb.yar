rule TTP_XOR_QUAD_CurrentVersionRun_c7bb {
  strings:
    $key_c7bb = { 94 d4 [2] b0 da [2] 9b f6 [2] b5 d4 [2] a1 cf [2] ae d5 [2] b0 c8 [2] b2 c9 [2] a9 cf [2] b5 c8 [2] a9 e7 }

  condition:
    any of them
}