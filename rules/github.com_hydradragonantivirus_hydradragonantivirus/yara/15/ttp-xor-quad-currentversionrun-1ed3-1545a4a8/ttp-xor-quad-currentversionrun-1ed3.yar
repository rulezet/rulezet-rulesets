rule TTP_XOR_QUAD_CurrentVersionRun_1ed3 {
  strings:
    $key_1ed3 = { 4d bc [2] 69 b2 [2] 42 9e [2] 6c bc [2] 78 a7 [2] 77 bd [2] 69 a0 [2] 6b a1 [2] 70 a7 [2] 6c a0 [2] 70 8f }

  condition:
    any of them
}