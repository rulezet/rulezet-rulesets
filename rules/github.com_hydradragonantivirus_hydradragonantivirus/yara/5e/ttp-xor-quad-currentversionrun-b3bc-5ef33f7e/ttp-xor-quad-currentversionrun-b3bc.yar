rule TTP_XOR_QUAD_CurrentVersionRun_b3bc {
  strings:
    $key_b3bc = { e0 d3 [2] c4 dd [2] ef f1 [2] c1 d3 [2] d5 c8 [2] da d2 [2] c4 cf [2] c6 ce [2] dd c8 [2] c1 cf [2] dd e0 }

  condition:
    any of them
}