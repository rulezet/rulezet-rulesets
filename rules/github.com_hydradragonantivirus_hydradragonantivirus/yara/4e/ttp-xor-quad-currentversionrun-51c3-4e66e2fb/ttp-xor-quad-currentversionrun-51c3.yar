rule TTP_XOR_QUAD_CurrentVersionRun_51c3 {
  strings:
    $key_51c3 = { 02 ac [2] 26 a2 [2] 0d 8e [2] 23 ac [2] 37 b7 [2] 38 ad [2] 26 b0 [2] 24 b1 [2] 3f b7 [2] 23 b0 [2] 3f 9f }

  condition:
    any of them
}