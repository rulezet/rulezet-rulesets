rule TTP_XOR_QUAD_CurrentVersionRun_7ed3 {
  strings:
    $key_7ed3 = { 2d bc [2] 09 b2 [2] 22 9e [2] 0c bc [2] 18 a7 [2] 17 bd [2] 09 a0 [2] 0b a1 [2] 10 a7 [2] 0c a0 [2] 10 8f }

  condition:
    any of them
}