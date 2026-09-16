rule TTP_XOR_QUAD_CurrentVersionRun_d7bb {
  strings:
    $key_d7bb = { 84 d4 [2] a0 da [2] 8b f6 [2] a5 d4 [2] b1 cf [2] be d5 [2] a0 c8 [2] a2 c9 [2] b9 cf [2] a5 c8 [2] b9 e7 }

  condition:
    any of them
}