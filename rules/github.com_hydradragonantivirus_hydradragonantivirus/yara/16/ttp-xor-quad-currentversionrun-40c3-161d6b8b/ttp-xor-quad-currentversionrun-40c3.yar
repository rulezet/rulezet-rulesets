rule TTP_XOR_QUAD_CurrentVersionRun_40c3 {
  strings:
    $key_40c3 = { 13 ac [2] 37 a2 [2] 1c 8e [2] 32 ac [2] 26 b7 [2] 29 ad [2] 37 b0 [2] 35 b1 [2] 2e b7 [2] 32 b0 [2] 2e 9f }

  condition:
    any of them
}