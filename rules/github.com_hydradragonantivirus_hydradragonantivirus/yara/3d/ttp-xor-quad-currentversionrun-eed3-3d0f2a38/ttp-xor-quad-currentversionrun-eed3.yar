rule TTP_XOR_QUAD_CurrentVersionRun_eed3 {
  strings:
    $key_eed3 = { bd bc [2] 99 b2 [2] b2 9e [2] 9c bc [2] 88 a7 [2] 87 bd [2] 99 a0 [2] 9b a1 [2] 80 a7 [2] 9c a0 [2] 80 8f }

  condition:
    any of them
}