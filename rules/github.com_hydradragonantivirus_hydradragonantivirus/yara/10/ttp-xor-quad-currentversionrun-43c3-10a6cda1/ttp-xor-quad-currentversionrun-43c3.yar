rule TTP_XOR_QUAD_CurrentVersionRun_43c3 {
  strings:
    $key_43c3 = { 10 ac [2] 34 a2 [2] 1f 8e [2] 31 ac [2] 25 b7 [2] 2a ad [2] 34 b0 [2] 36 b1 [2] 2d b7 [2] 31 b0 [2] 2d 9f }

  condition:
    any of them
}