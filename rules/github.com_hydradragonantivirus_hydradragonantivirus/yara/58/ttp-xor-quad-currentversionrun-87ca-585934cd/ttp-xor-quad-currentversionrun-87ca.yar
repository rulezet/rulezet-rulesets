rule TTP_XOR_QUAD_CurrentVersionRun_87ca {
  strings:
    $key_87ca = { d4 a5 [2] f0 ab [2] db 87 [2] f5 a5 [2] e1 be [2] ee a4 [2] f0 b9 [2] f2 b8 [2] e9 be [2] f5 b9 [2] e9 96 }

  condition:
    any of them
}