rule TTP_XOR_QUAD_CurrentVersionRun_fbd3 {
  strings:
    $key_fbd3 = { a8 bc [2] 8c b2 [2] a7 9e [2] 89 bc [2] 9d a7 [2] 92 bd [2] 8c a0 [2] 8e a1 [2] 95 a7 [2] 89 a0 [2] 95 8f }

  condition:
    any of them
}