rule TTP_XOR_QUAD_CurrentVersionRun_23c3 {
  strings:
    $key_23c3 = { 70 ac [2] 54 a2 [2] 7f 8e [2] 51 ac [2] 45 b7 [2] 4a ad [2] 54 b0 [2] 56 b1 [2] 4d b7 [2] 51 b0 [2] 4d 9f }

  condition:
    any of them
}