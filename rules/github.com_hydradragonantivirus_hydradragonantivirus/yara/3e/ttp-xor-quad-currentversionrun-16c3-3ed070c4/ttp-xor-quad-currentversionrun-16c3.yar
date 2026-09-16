rule TTP_XOR_QUAD_CurrentVersionRun_16c3 {
  strings:
    $key_16c3 = { 45 ac [2] 61 a2 [2] 4a 8e [2] 64 ac [2] 70 b7 [2] 7f ad [2] 61 b0 [2] 63 b1 [2] 78 b7 [2] 64 b0 [2] 78 9f }

  condition:
    any of them
}