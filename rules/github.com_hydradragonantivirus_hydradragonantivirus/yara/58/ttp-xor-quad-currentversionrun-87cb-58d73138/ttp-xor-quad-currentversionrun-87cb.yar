rule TTP_XOR_QUAD_CurrentVersionRun_87cb {
  strings:
    $key_87cb = { d4 a4 [2] f0 aa [2] db 86 [2] f5 a4 [2] e1 bf [2] ee a5 [2] f0 b8 [2] f2 b9 [2] e9 bf [2] f5 b8 [2] e9 97 }

  condition:
    any of them
}