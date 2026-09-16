rule TTP_XOR_QUAD_CurrentVersionRun_87cf {
  strings:
    $key_87cf = { d4 a0 [2] f0 ae [2] db 82 [2] f5 a0 [2] e1 bb [2] ee a1 [2] f0 bc [2] f2 bd [2] e9 bb [2] f5 bc [2] e9 93 }

  condition:
    any of them
}