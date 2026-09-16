rule TTP_XOR_QUAD_CurrentVersionRun_a1bd {
  strings:
    $key_a1bd = { f2 d2 [2] d6 dc [2] fd f0 [2] d3 d2 [2] c7 c9 [2] c8 d3 [2] d6 ce [2] d4 cf [2] cf c9 [2] d3 ce [2] cf e1 }

  condition:
    any of them
}