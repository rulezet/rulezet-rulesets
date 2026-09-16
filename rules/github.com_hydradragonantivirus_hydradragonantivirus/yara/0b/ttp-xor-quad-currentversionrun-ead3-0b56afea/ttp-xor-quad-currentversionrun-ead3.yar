rule TTP_XOR_QUAD_CurrentVersionRun_ead3 {
  strings:
    $key_ead3 = { b9 bc [2] 9d b2 [2] b6 9e [2] 98 bc [2] 8c a7 [2] 83 bd [2] 9d a0 [2] 9f a1 [2] 84 a7 [2] 98 a0 [2] 84 8f }

  condition:
    any of them
}