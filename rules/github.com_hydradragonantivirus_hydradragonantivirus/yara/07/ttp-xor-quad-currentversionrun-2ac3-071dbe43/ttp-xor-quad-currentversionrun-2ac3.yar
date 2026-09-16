rule TTP_XOR_QUAD_CurrentVersionRun_2ac3 {
  strings:
    $key_2ac3 = { 79 ac [2] 5d a2 [2] 76 8e [2] 58 ac [2] 4c b7 [2] 43 ad [2] 5d b0 [2] 5f b1 [2] 44 b7 [2] 58 b0 [2] 44 9f }

  condition:
    any of them
}