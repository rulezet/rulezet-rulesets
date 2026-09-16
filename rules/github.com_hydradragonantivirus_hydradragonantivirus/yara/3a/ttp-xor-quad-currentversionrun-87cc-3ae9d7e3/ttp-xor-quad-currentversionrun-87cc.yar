rule TTP_XOR_QUAD_CurrentVersionRun_87cc {
  strings:
    $key_87cc = { d4 a3 [2] f0 ad [2] db 81 [2] f5 a3 [2] e1 b8 [2] ee a2 [2] f0 bf [2] f2 be [2] e9 b8 [2] f5 bf [2] e9 90 }

  condition:
    any of them
}