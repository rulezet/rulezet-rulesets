rule TTP_XOR_QUAD_CurrentVersionRun_87cd {
  strings:
    $key_87cd = { d4 a2 [2] f0 ac [2] db 80 [2] f5 a2 [2] e1 b9 [2] ee a3 [2] f0 be [2] f2 bf [2] e9 b9 [2] f5 be [2] e9 91 }

  condition:
    any of them
}