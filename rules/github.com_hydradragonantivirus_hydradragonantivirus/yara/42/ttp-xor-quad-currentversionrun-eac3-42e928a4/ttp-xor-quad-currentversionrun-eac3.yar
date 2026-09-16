rule TTP_XOR_QUAD_CurrentVersionRun_eac3 {
  strings:
    $key_eac3 = { b9 ac [2] 9d a2 [2] b6 8e [2] 98 ac [2] 8c b7 [2] 83 ad [2] 9d b0 [2] 9f b1 [2] 84 b7 [2] 98 b0 [2] 84 9f }

  condition:
    any of them
}