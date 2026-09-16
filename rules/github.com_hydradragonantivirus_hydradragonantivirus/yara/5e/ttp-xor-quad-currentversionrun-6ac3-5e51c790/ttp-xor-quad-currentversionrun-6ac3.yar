rule TTP_XOR_QUAD_CurrentVersionRun_6ac3 {
  strings:
    $key_6ac3 = { 39 ac [2] 1d a2 [2] 36 8e [2] 18 ac [2] 0c b7 [2] 03 ad [2] 1d b0 [2] 1f b1 [2] 04 b7 [2] 18 b0 [2] 04 9f }

  condition:
    any of them
}