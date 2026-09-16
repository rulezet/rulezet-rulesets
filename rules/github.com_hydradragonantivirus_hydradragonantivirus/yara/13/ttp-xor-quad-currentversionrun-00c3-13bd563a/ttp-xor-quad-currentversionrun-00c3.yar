rule TTP_XOR_QUAD_CurrentVersionRun_00c3 {
  strings:
    $key_00c3 = { 53 ac [2] 77 a2 [2] 5c 8e [2] 72 ac [2] 66 b7 [2] 69 ad [2] 77 b0 [2] 75 b1 [2] 6e b7 [2] 72 b0 [2] 6e 9f }

  condition:
    any of them
}