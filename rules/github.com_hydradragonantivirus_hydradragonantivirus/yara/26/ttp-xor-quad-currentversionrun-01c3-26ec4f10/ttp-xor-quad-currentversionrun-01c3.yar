rule TTP_XOR_QUAD_CurrentVersionRun_01c3 {
  strings:
    $key_01c3 = { 52 ac [2] 76 a2 [2] 5d 8e [2] 73 ac [2] 67 b7 [2] 68 ad [2] 76 b0 [2] 74 b1 [2] 6f b7 [2] 73 b0 [2] 6f 9f }

  condition:
    any of them
}