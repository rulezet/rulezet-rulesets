rule TTP_XOR_QUAD_CurrentVersionRun_1bc3 {
  strings:
    $key_1bc3 = { 48 ac [2] 6c a2 [2] 47 8e [2] 69 ac [2] 7d b7 [2] 72 ad [2] 6c b0 [2] 6e b1 [2] 75 b7 [2] 69 b0 [2] 75 9f }

  condition:
    any of them
}