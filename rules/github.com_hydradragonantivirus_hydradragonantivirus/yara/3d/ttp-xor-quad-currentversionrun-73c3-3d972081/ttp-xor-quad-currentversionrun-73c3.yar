rule TTP_XOR_QUAD_CurrentVersionRun_73c3 {
  strings:
    $key_73c3 = { 20 ac [2] 04 a2 [2] 2f 8e [2] 01 ac [2] 15 b7 [2] 1a ad [2] 04 b0 [2] 06 b1 [2] 1d b7 [2] 01 b0 [2] 1d 9f }

  condition:
    any of them
}