rule TTP_XOR_QUAD_CurrentVersionRun_84c3 {
  strings:
    $key_84c3 = { d7 ac [2] f3 a2 [2] d8 8e [2] f6 ac [2] e2 b7 [2] ed ad [2] f3 b0 [2] f1 b1 [2] ea b7 [2] f6 b0 [2] ea 9f }

  condition:
    any of them
}