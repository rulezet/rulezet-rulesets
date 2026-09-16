rule TTP_XOR_QUAD_CurrentVersionRun_fac3 {
  strings:
    $key_fac3 = { a9 ac [2] 8d a2 [2] a6 8e [2] 88 ac [2] 9c b7 [2] 93 ad [2] 8d b0 [2] 8f b1 [2] 94 b7 [2] 88 b0 [2] 94 9f }

  condition:
    any of them
}