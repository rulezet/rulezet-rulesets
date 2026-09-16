rule TTP_XOR_QUAD_CurrentVersionRun_27c3 {
  strings:
    $key_27c3 = { 74 ac [2] 50 a2 [2] 7b 8e [2] 55 ac [2] 41 b7 [2] 4e ad [2] 50 b0 [2] 52 b1 [2] 49 b7 [2] 55 b0 [2] 49 9f }

  condition:
    any of them
}