rule TTP_XOR_QUAD_CurrentVersionRun_b1c3 {
  strings:
    $key_b1c3 = { e2 ac [2] c6 a2 [2] ed 8e [2] c3 ac [2] d7 b7 [2] d8 ad [2] c6 b0 [2] c4 b1 [2] df b7 [2] c3 b0 [2] df 9f }

  condition:
    any of them
}