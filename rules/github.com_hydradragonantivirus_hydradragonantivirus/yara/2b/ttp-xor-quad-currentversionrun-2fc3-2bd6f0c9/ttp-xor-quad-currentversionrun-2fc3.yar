rule TTP_XOR_QUAD_CurrentVersionRun_2fc3 {
  strings:
    $key_2fc3 = { 7c ac [2] 58 a2 [2] 73 8e [2] 5d ac [2] 49 b7 [2] 46 ad [2] 58 b0 [2] 5a b1 [2] 41 b7 [2] 5d b0 [2] 41 9f }

  condition:
    any of them
}