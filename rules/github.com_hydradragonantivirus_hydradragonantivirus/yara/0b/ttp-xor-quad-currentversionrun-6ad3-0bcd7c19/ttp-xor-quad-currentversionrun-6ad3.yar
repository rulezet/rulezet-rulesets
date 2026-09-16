rule TTP_XOR_QUAD_CurrentVersionRun_6ad3 {
  strings:
    $key_6ad3 = { 39 bc [2] 1d b2 [2] 36 9e [2] 18 bc [2] 0c a7 [2] 03 bd [2] 1d a0 [2] 1f a1 [2] 04 a7 [2] 18 a0 [2] 04 8f }

  condition:
    any of them
}