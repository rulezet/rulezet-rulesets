rule TTP_XOR_QUAD_CurrentVersionRun_83c3 {
  strings:
    $key_83c3 = { d0 ac [2] f4 a2 [2] df 8e [2] f1 ac [2] e5 b7 [2] ea ad [2] f4 b0 [2] f6 b1 [2] ed b7 [2] f1 b0 [2] ed 9f }

  condition:
    any of them
}