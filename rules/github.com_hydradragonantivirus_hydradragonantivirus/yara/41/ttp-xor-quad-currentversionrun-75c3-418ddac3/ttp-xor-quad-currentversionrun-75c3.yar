rule TTP_XOR_QUAD_CurrentVersionRun_75c3 {
  strings:
    $key_75c3 = { 26 ac [2] 02 a2 [2] 29 8e [2] 07 ac [2] 13 b7 [2] 1c ad [2] 02 b0 [2] 00 b1 [2] 1b b7 [2] 07 b0 [2] 1b 9f }

  condition:
    any of them
}