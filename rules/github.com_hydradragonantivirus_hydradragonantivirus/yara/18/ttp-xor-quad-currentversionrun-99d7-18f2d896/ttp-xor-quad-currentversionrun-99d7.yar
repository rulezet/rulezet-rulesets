rule TTP_XOR_QUAD_CurrentVersionRun_99d7 {
  strings:
    $key_99d7 = { ca b8 [2] ee b6 [2] c5 9a [2] eb b8 [2] ff a3 [2] f0 b9 [2] ee a4 [2] ec a5 [2] f7 a3 [2] eb a4 [2] f7 8b }

  condition:
    any of them
}