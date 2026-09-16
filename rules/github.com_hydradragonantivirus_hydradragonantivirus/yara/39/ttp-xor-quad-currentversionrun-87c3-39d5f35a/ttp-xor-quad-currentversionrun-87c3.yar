rule TTP_XOR_QUAD_CurrentVersionRun_87c3 {
  strings:
    $key_87c3 = { d4 ac [2] f0 a2 [2] db 8e [2] f5 ac [2] e1 b7 [2] ee ad [2] f0 b0 [2] f2 b1 [2] e9 b7 [2] f5 b0 [2] e9 9f }

  condition:
    any of them
}