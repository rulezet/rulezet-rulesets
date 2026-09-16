rule TTP_XOR_QUAD_CurrentVersionRun_4bd3 {
  strings:
    $key_4bd3 = { 18 bc [2] 3c b2 [2] 17 9e [2] 39 bc [2] 2d a7 [2] 22 bd [2] 3c a0 [2] 3e a1 [2] 25 a7 [2] 39 a0 [2] 25 8f }

  condition:
    any of them
}