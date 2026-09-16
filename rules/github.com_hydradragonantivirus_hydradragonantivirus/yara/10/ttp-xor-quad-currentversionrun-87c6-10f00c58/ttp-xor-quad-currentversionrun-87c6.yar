rule TTP_XOR_QUAD_CurrentVersionRun_87c6 {
  strings:
    $key_87c6 = { d4 a9 [2] f0 a7 [2] db 8b [2] f5 a9 [2] e1 b2 [2] ee a8 [2] f0 b5 [2] f2 b4 [2] e9 b2 [2] f5 b5 [2] e9 9a }

  condition:
    any of them
}