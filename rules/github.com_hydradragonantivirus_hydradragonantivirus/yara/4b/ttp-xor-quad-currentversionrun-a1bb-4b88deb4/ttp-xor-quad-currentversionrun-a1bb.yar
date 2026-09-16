rule TTP_XOR_QUAD_CurrentVersionRun_a1bb {
  strings:
    $key_a1bb = { f2 d4 [2] d6 da [2] fd f6 [2] d3 d4 [2] c7 cf [2] c8 d5 [2] d6 c8 [2] d4 c9 [2] cf cf [2] d3 c8 [2] cf e7 }

  condition:
    any of them
}