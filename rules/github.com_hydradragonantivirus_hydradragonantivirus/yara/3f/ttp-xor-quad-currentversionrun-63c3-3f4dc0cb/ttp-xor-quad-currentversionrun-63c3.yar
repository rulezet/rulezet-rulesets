rule TTP_XOR_QUAD_CurrentVersionRun_63c3 {
  strings:
    $key_63c3 = { 30 ac [2] 14 a2 [2] 3f 8e [2] 11 ac [2] 05 b7 [2] 0a ad [2] 14 b0 [2] 16 b1 [2] 0d b7 [2] 11 b0 [2] 0d 9f }

  condition:
    any of them
}