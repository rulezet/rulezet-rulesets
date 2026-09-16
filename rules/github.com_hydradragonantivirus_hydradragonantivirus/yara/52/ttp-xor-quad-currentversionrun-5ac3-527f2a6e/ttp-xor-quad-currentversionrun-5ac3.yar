rule TTP_XOR_QUAD_CurrentVersionRun_5ac3 {
  strings:
    $key_5ac3 = { 09 ac [2] 2d a2 [2] 06 8e [2] 28 ac [2] 3c b7 [2] 33 ad [2] 2d b0 [2] 2f b1 [2] 34 b7 [2] 28 b0 [2] 34 9f }

  condition:
    any of them
}