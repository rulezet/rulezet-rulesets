rule TTP_XOR_QUAD_CurrentVersionRun_f9d3 {
  strings:
    $key_f9d3 = { aa bc [2] 8e b2 [2] a5 9e [2] 8b bc [2] 9f a7 [2] 90 bd [2] 8e a0 [2] 8c a1 [2] 97 a7 [2] 8b a0 [2] 97 8f }

  condition:
    any of them
}