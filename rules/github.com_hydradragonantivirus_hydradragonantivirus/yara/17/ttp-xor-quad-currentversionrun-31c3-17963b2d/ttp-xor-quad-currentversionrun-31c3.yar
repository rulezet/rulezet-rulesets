rule TTP_XOR_QUAD_CurrentVersionRun_31c3 {
  strings:
    $key_31c3 = { 62 ac [2] 46 a2 [2] 6d 8e [2] 43 ac [2] 57 b7 [2] 58 ad [2] 46 b0 [2] 44 b1 [2] 5f b7 [2] 43 b0 [2] 5f 9f }

  condition:
    any of them
}