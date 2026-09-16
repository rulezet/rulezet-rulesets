rule TTP_XOR_QUAD_CurrentVersionRun_18d3 {
  strings:
    $key_18d3 = { 4b bc [2] 6f b2 [2] 44 9e [2] 6a bc [2] 7e a7 [2] 71 bd [2] 6f a0 [2] 6d a1 [2] 76 a7 [2] 6a a0 [2] 76 8f }

  condition:
    any of them
}