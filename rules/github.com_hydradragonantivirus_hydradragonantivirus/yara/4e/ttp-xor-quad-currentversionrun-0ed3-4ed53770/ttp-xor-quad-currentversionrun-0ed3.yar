rule TTP_XOR_QUAD_CurrentVersionRun_0ed3 {
  strings:
    $key_0ed3 = { 5d bc [2] 79 b2 [2] 52 9e [2] 7c bc [2] 68 a7 [2] 67 bd [2] 79 a0 [2] 7b a1 [2] 60 a7 [2] 7c a0 [2] 60 8f }

  condition:
    any of them
}