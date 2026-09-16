rule TTP_XOR_QUAD_CurrentVersionRun_07c3 {
  strings:
    $key_07c3 = { 54 ac [2] 70 a2 [2] 5b 8e [2] 75 ac [2] 61 b7 [2] 6e ad [2] 70 b0 [2] 72 b1 [2] 69 b7 [2] 75 b0 [2] 69 9f }

  condition:
    any of them
}