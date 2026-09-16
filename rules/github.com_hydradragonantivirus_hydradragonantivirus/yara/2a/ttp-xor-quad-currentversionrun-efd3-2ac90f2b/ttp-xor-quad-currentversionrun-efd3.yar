rule TTP_XOR_QUAD_CurrentVersionRun_efd3 {
  strings:
    $key_efd3 = { bc bc [2] 98 b2 [2] b3 9e [2] 9d bc [2] 89 a7 [2] 86 bd [2] 98 a0 [2] 9a a1 [2] 81 a7 [2] 9d a0 [2] 81 8f }

  condition:
    any of them
}