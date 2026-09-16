rule TTP_XOR_QUAD_CurrentVersionRun_0dc3 {
  strings:
    $key_0dc3 = { 5e ac [2] 7a a2 [2] 51 8e [2] 7f ac [2] 6b b7 [2] 64 ad [2] 7a b0 [2] 78 b1 [2] 63 b7 [2] 7f b0 [2] 63 9f }

  condition:
    any of them
}