rule TTP_XOR_QUAD_CurrentVersionRun_a7bb {
  strings:
    $key_a7bb = { f4 d4 [2] d0 da [2] fb f6 [2] d5 d4 [2] c1 cf [2] ce d5 [2] d0 c8 [2] d2 c9 [2] c9 cf [2] d5 c8 [2] c9 e7 }

  condition:
    any of them
}