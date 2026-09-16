rule TTP_XOR_QUAD_CurrentVersionRun_3ac3 {
  strings:
    $key_3ac3 = { 69 ac [2] 4d a2 [2] 66 8e [2] 48 ac [2] 5c b7 [2] 53 ad [2] 4d b0 [2] 4f b1 [2] 54 b7 [2] 48 b0 [2] 54 9f }

  condition:
    any of them
}