rule TTP_XOR_QUAD_CurrentVersionRun_1ac3 {
  strings:
    $key_1ac3 = { 49 ac [2] 6d a2 [2] 46 8e [2] 68 ac [2] 7c b7 [2] 73 ad [2] 6d b0 [2] 6f b1 [2] 74 b7 [2] 68 b0 [2] 74 9f }

  condition:
    any of them
}