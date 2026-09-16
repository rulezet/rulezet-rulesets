rule TTP_XOR_QUAD_CurrentVersionRun_f0d3 {
  strings:
    $key_f0d3 = { a3 bc [2] 87 b2 [2] ac 9e [2] 82 bc [2] 96 a7 [2] 99 bd [2] 87 a0 [2] 85 a1 [2] 9e a7 [2] 82 a0 [2] 9e 8f }

  condition:
    any of them
}