rule TTP_XOR_QUAD_CurrentVersionRun_c1bb {
  strings:
    $key_c1bb = { 92 d4 [2] b6 da [2] 9d f6 [2] b3 d4 [2] a7 cf [2] a8 d5 [2] b6 c8 [2] b4 c9 [2] af cf [2] b3 c8 [2] af e7 }

  condition:
    any of them
}