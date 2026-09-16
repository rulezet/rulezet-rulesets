rule TTP_XOR_QUAD_CurrentVersionRun_f8c3 {
  strings:
    $key_f8c3 = { ab ac [2] 8f a2 [2] a4 8e [2] 8a ac [2] 9e b7 [2] 91 ad [2] 8f b0 [2] 8d b1 [2] 96 b7 [2] 8a b0 [2] 96 9f }

  condition:
    any of them
}