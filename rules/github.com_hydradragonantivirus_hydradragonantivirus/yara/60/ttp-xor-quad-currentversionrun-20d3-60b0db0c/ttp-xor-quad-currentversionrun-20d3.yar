rule TTP_XOR_QUAD_CurrentVersionRun_20d3 {
  strings:
    $key_20d3 = { 73 bc [2] 57 b2 [2] 7c 9e [2] 52 bc [2] 46 a7 [2] 49 bd [2] 57 a0 [2] 55 a1 [2] 4e a7 [2] 52 a0 [2] 4e 8f }

  condition:
    any of them
}