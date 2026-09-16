rule TTP_XOR_QUAD_CurrentVersionRun_e2a0 {
  strings:
    $key_e2a0 = { b1 cf [2] 95 c1 [2] be ed [2] 90 cf [2] 84 d4 [2] 8b ce [2] 95 d3 [2] 97 d2 [2] 8c d4 [2] 90 d3 [2] 8c fc }

  condition:
    any of them
}