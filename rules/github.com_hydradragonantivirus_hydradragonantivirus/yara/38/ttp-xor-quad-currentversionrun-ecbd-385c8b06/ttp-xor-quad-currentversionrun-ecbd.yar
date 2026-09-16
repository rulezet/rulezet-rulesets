rule TTP_XOR_QUAD_CurrentVersionRun_ecbd {
  strings:
    $key_ecbd = { bf d2 [2] 9b dc [2] b0 f0 [2] 9e d2 [2] 8a c9 [2] 85 d3 [2] 9b ce [2] 99 cf [2] 82 c9 [2] 9e ce [2] 82 e1 }

  condition:
    any of them
}