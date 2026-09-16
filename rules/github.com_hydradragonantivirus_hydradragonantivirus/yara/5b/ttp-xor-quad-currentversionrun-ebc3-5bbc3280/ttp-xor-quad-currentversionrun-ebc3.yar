rule TTP_XOR_QUAD_CurrentVersionRun_ebc3 {
  strings:
    $key_ebc3 = { b8 ac [2] 9c a2 [2] b7 8e [2] 99 ac [2] 8d b7 [2] 82 ad [2] 9c b0 [2] 9e b1 [2] 85 b7 [2] 99 b0 [2] 85 9f }

  condition:
    any of them
}