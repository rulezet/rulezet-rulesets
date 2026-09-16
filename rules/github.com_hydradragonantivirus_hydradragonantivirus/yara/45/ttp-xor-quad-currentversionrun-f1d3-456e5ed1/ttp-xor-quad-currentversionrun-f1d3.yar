rule TTP_XOR_QUAD_CurrentVersionRun_f1d3 {
  strings:
    $key_f1d3 = { a2 bc [2] 86 b2 [2] ad 9e [2] 83 bc [2] 97 a7 [2] 98 bd [2] 86 a0 [2] 84 a1 [2] 9f a7 [2] 83 a0 [2] 9f 8f }

  condition:
    any of them
}