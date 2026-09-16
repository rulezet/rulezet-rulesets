rule TTP_XOR_QUAD_CurrentVersionRun_40d3 {
  strings:
    $key_40d3 = { 13 bc [2] 37 b2 [2] 1c 9e [2] 32 bc [2] 26 a7 [2] 29 bd [2] 37 a0 [2] 35 a1 [2] 2e a7 [2] 32 a0 [2] 2e 8f }

  condition:
    any of them
}