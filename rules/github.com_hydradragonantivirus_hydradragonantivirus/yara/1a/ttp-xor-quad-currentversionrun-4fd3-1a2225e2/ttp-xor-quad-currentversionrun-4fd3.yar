rule TTP_XOR_QUAD_CurrentVersionRun_4fd3 {
  strings:
    $key_4fd3 = { 1c bc [2] 38 b2 [2] 13 9e [2] 3d bc [2] 29 a7 [2] 26 bd [2] 38 a0 [2] 3a a1 [2] 21 a7 [2] 3d a0 [2] 21 8f }

  condition:
    any of them
}