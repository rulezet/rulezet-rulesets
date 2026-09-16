rule TTP_XOR_QUAD_CurrentVersionRun_57c3 {
  strings:
    $key_57c3 = { 04 ac [2] 20 a2 [2] 0b 8e [2] 25 ac [2] 31 b7 [2] 3e ad [2] 20 b0 [2] 22 b1 [2] 39 b7 [2] 25 b0 [2] 39 9f }

  condition:
    any of them
}