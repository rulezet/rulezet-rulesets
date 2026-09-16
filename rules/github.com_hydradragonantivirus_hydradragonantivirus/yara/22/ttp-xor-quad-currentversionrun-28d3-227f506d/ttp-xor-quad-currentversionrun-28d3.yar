rule TTP_XOR_QUAD_CurrentVersionRun_28d3 {
  strings:
    $key_28d3 = { 7b bc [2] 5f b2 [2] 74 9e [2] 5a bc [2] 4e a7 [2] 41 bd [2] 5f a0 [2] 5d a1 [2] 46 a7 [2] 5a a0 [2] 46 8f }

  condition:
    any of them
}