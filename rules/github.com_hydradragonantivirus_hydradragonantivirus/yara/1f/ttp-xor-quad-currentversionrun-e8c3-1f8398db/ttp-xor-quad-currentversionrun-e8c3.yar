rule TTP_XOR_QUAD_CurrentVersionRun_e8c3 {
  strings:
    $key_e8c3 = { bb ac [2] 9f a2 [2] b4 8e [2] 9a ac [2] 8e b7 [2] 81 ad [2] 9f b0 [2] 9d b1 [2] 86 b7 [2] 9a b0 [2] 86 9f }

  condition:
    any of them
}