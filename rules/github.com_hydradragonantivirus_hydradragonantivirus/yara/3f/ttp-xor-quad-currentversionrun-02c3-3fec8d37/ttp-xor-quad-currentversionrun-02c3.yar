rule TTP_XOR_QUAD_CurrentVersionRun_02c3 {
  strings:
    $key_02c3 = { 51 ac [2] 75 a2 [2] 5e 8e [2] 70 ac [2] 64 b7 [2] 6b ad [2] 75 b0 [2] 77 b1 [2] 6c b7 [2] 70 b0 [2] 6c 9f }

  condition:
    any of them
}