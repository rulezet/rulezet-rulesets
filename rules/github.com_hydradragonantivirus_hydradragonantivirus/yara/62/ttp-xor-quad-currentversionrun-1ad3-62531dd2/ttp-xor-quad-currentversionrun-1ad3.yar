rule TTP_XOR_QUAD_CurrentVersionRun_1ad3 {
  strings:
    $key_1ad3 = { 49 bc [2] 6d b2 [2] 46 9e [2] 68 bc [2] 7c a7 [2] 73 bd [2] 6d a0 [2] 6f a1 [2] 74 a7 [2] 68 a0 [2] 74 8f }

  condition:
    any of them
}